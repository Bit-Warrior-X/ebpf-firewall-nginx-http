#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>


//----------------------------------------------------------------------
// 1) MAIN‐LEVEL (HTTP) CONFIG STRUCT
//----------------------------------------------------------------------
// Holds the health‐check interval (ms) and a list of all loc_confs
// that have report_socket_path set.
typedef struct {
    ngx_msec_t                 health_interval;   // in ms, how often to ping
    ngx_array_t               *loc_confs;         // array of ngx_http_report_ip_loc_conf_t*
} ngx_http_report_ip_main_conf_t;


//----------------------------------------------------------------------
// 2) LOCATION‐LEVEL CONFIG STRUCT
//----------------------------------------------------------------------
// One per “location” (or server) where directives are used.
typedef struct {
    ngx_uint_t    methods_mask; // bitmask of allowed methods (GET, POST, etc.)
    ngx_str_t     socket_path;  // e.g. "/var/run/report_ip.sock"
    int           sock_fd;      // –1 = not opened (or closed); ≥0 = valid AF_UNIX DGRAM FD
    ngx_flag_t    enabled;      // 1 = health‐check says “socket is live”; 0 = “dead, skip sends”
} ngx_http_report_ip_loc_conf_t;


//----------------------------------------------------------------------
// 3) FORWARD DECLARATIONS
//----------------------------------------------------------------------

static void * ngx_http_report_ip_create_main_conf(ngx_conf_t *cf);
static char * ngx_http_report_ip_init_main_conf(ngx_conf_t *cf, void *conf);


static void * ngx_http_report_ip_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_report_ip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_report_ip_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_report_ip_init_process(ngx_cycle_t *cycle);
static void ngx_http_report_ip_health_check_handler(ngx_event_t *ev);

static ngx_int_t ngx_http_report_ip_handler(ngx_http_request_t *r);

static char * ngx_http_report_ip_set_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


//----------------------------------------------------------------------
// 4) MODULE DIRECTIVES
//----------------------------------------------------------------------

static ngx_command_t ngx_http_report_ip_commands[] = {

    // HTTP‐level directive: how often (ms) to ping the socket
    { ngx_string("report_healthcheck_interval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_report_ip_main_conf_t, health_interval),
      NULL },

    // Location‐level: allow these methods (bitmask of GET, POST, PUT, etc.)
    { ngx_string("report_available_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_report_ip_set_methods,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_report_ip_loc_conf_t, methods_mask),
      NULL },

    // Location‐level: path to Unix socket
    { ngx_string("report_socket_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_report_ip_loc_conf_t, socket_path),
      NULL },

    ngx_null_command
};


//----------------------------------------------------------------------
// 5) MODULE CONTEXT
//----------------------------------------------------------------------

static ngx_http_module_t ngx_http_report_ip_module_ctx = {
    // preconfiguration
    NULL,
    // postconfiguration
    ngx_http_report_ip_init,

    // create main_conf
    ngx_http_report_ip_create_main_conf,
    // init main_conf
    ngx_http_report_ip_init_main_conf,

    // create server_conf
    NULL,
    // merge server_conf
    NULL,

    // create loc_conf
    ngx_http_report_ip_create_loc_conf,
    // merge loc_conf
    ngx_http_report_ip_merge_loc_conf
};


//----------------------------------------------------------------------
// 6) MODULE DEFINITION
//----------------------------------------------------------------------

ngx_module_t ngx_http_report_ip_module = {
    NGX_MODULE_V1,
    &ngx_http_report_ip_module_ctx,  // module context
    ngx_http_report_ip_commands,     // module directives
    NGX_HTTP_MODULE,                 // module type
    NULL,                            // init master (none needed)
    NULL,                            // init module (none needed)
    ngx_http_report_ip_init_process, // init process – to start health‐check timer
    NULL,                            // init thread
    NULL,                            // exit thread
    NULL,                            // exit process
    NULL,                            // exit master
    NGX_MODULE_V1_PADDING
};


//----------------------------------------------------------------------
// 7) CREATE & MERGE MAIN CONF
//----------------------------------------------------------------------

static void *
ngx_http_report_ip_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_report_ip_main_conf_t  *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_report_ip_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    // health_interval unset → will default to 1000 ms in merge
    mcf->health_interval = NGX_CONF_UNSET_MSEC;

    // We create the array now to hold pointers to each loc_conf
    // (initially empty; capacity=4).
    mcf->loc_confs = ngx_array_create(cf->pool, 4, sizeof(ngx_http_report_ip_loc_conf_t *));
    if (mcf->loc_confs == NULL) {
        return NULL;
    }

    return mcf;
}


static char *
ngx_http_report_ip_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_report_ip_main_conf_t *main_conf = (ngx_http_report_ip_main_conf_t *) conf;

    if (cf ==NULL || conf == NULL)
        return NGX_CONF_ERROR;
    
    main_conf->health_interval = 1000;
    return NGX_CONF_OK;
}


//----------------------------------------------------------------------
// 8) CREATE & MERGE LOC CONF
//----------------------------------------------------------------------

static void *
ngx_http_report_ip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_report_ip_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_report_ip_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    // methods_mask unset → merge will default to GET|POST
    conf->methods_mask = NGX_CONF_UNSET_UINT;

    ngx_str_null(&conf->socket_path);

    // No FD open at first
    conf->sock_fd = -1;

    // Enabled=1 means “we will attempt to send/ping until proven dead”
    conf->enabled = 1;

    return conf;
}


static char *
ngx_http_report_ip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_report_ip_loc_conf_t  *prev = parent;
    ngx_http_report_ip_loc_conf_t  *conf = child;
    ngx_http_report_ip_main_conf_t *mcf;

    // 1) If user never set report_available_methods, default GET|POST
    ngx_conf_merge_uint_value(conf->methods_mask,
                              prev->methods_mask,
                              (NGX_HTTP_GET|NGX_HTTP_POST));

    // 2) Merge socket_path; if still empty → error
    ngx_conf_merge_str_value(conf->socket_path,
                             prev->socket_path,
                             "");

    if (conf->socket_path.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "report_socket_path must be specified");
        return NGX_CONF_ERROR;
    }

    // 3) Initialize runtime fields (each worker will overwrite these when needed):
    conf->sock_fd = -1;
    conf->enabled = 1;

    // 4) Register this loc_conf in the global list so health‐check knows about it.
    //    We grab the main_conf pointer and push &conf into loc_confs array.
    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_report_ip_module);
    if (mcf->loc_confs == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "internal error: loc_confs array not created");
        return NGX_CONF_ERROR;
    }

    // Push a pointer to this newly‐merged loc_conf into the array
    ngx_http_report_ip_loc_conf_t **slot =
        ngx_array_push(mcf->loc_confs);
    if (slot == NULL) {
        return NGX_CONF_ERROR;
    }
    *slot = conf;
    return NGX_CONF_OK;
}


//----------------------------------------------------------------------
// 9) PARSE “report_available_methods” (bitmask of GET, POST, etc.)
//----------------------------------------------------------------------

static char *
ngx_http_report_ip_set_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_report_ip_loc_conf_t  *lcf = conf;
    ngx_str_t                      *value;
    ngx_uint_t                      i;

    // We expect: report_available_methods  METHOD1 METHOD2 … ;
    // cf->args->elts is an array of ngx_str_t with [0] = "report_available_methods",
    // [1] = first method, [2] = second method, etc.
    value = cf->args->elts;

    // Reset the mask to zero before parsing
    lcf->methods_mask = 0;

    // Start at i=1 to skip the directive name itself
    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcasecmp(value[i].data, (u_char *) "GET") == 0) {
            lcf->methods_mask |= NGX_HTTP_GET;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "HEAD") == 0) {
            lcf->methods_mask |= NGX_HTTP_HEAD;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "POST") == 0) {
            lcf->methods_mask |= NGX_HTTP_POST;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "PUT") == 0) {
            lcf->methods_mask |= NGX_HTTP_PUT;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "DELETE") == 0) {
            lcf->methods_mask |= NGX_HTTP_DELETE;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "MKCOL") == 0) {
            lcf->methods_mask |= NGX_HTTP_MKCOL;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "COPY") == 0) {
            lcf->methods_mask |= NGX_HTTP_COPY;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "MOVE") == 0) {
            lcf->methods_mask |= NGX_HTTP_MOVE;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "OPTIONS") == 0) {
            lcf->methods_mask |= NGX_HTTP_OPTIONS;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "PROPFIND") == 0) {
            lcf->methods_mask |= NGX_HTTP_PROPFIND;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "PROPPATCH") == 0) {
            lcf->methods_mask |= NGX_HTTP_PROPPATCH;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "LOCK") == 0) {
            lcf->methods_mask |= NGX_HTTP_LOCK;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "UNLOCK") == 0) {
            lcf->methods_mask |= NGX_HTTP_UNLOCK;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "PATCH") == 0) {
            lcf->methods_mask |= NGX_HTTP_PATCH;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "TRACE") == 0) {
            lcf->methods_mask |= NGX_HTTP_TRACE;
            continue;
        }

        if (ngx_strcasecmp(value[i].data, (u_char *) "CONNECT") == 0) {
            lcf->methods_mask |= NGX_HTTP_CONNECT;
            continue;
        }

        // If we get here, it wasn’t one of the recognized tokens:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid method \"%V\" in \"report_available_methods\"",
                           &value[i]);
        return NGX_CONF_ERROR;
    }

    // If the user wrote no methods (e.g., `report_available_methods;`), that's also an error.
    if (lcf->methods_mask == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"report_available_methods\" requires at least one method");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

//----------------------------------------------------------------------
// 10) THE REQUEST HANDLER (ACCESS PHASE)
//----------------------------------------------------------------------

static ngx_int_t
ngx_http_report_ip_handler(ngx_http_request_t *r)
{
    ngx_http_report_ip_loc_conf_t  *conf;
    ngx_str_t                       addr_text;
    struct sockaddr_un              uaddr;
    ssize_t                         sent;
    ngx_err_t                       err;
    ngx_log_t                      *log;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_report_ip_module);
    log  = r->connection->log;

    // 1) If request method is allowed (in bitmask), do nothing:
    if (r->method & conf->methods_mask) {
        return NGX_DECLINED;
    }

    // 2) If health‐check has marked this socket “dead,” skip any send:
    if (!conf->enabled || conf->sock_fd < 0) {
        return NGX_DECLINED;
    }

    // 3) Get client IP text (e.g. "203.0.113.42")
    addr_text = r->connection->addr_text;
    if (addr_text.len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "report_ip: cannot retrieve client addr_text");
        return NGX_DECLINED;
    }

    // 4) Prepare the sockaddr_un to send to
    ngx_memzero(&uaddr, sizeof(struct sockaddr_un));
    uaddr.sun_family = AF_UNIX;
    ngx_memcpy(uaddr.sun_path, conf->socket_path.data, conf->socket_path.len);
    uaddr.sun_path[conf->socket_path.len] = '\0';

    u_char  buffer[128];
    u_char *p;

    p = ngx_snprintf(buffer,
                         sizeof(buffer),
                         "block:%V",
                         &addr_text);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "report_ip: ngx_snprintf truncated message for \"%V\"",
                      &addr_text);
        return NGX_DECLINED;
    }
    
    size_t msg_len = p - buffer;
    
    // 5) Try to send the IP string
    sent = sendto(conf->sock_fd,
                  buffer,
                  msg_len,
                  0,
                  (struct sockaddr *) &uaddr,
                  sizeof(struct sockaddr_un));

    if (sent < 0) {
        err = ngx_errno;

        // If sendto() fails (socket vanished, no listener, etc.), disable it now.
        ngx_log_error(NGX_LOG_ERR, log, err,
                      "report_ip: sendto() failed, disabling future sends: \"%V\"",
                      &conf->socket_path);

        close(conf->sock_fd);
        conf->sock_fd = -1;
        conf->enabled = 0;

        return NGX_DECLINED;
    }

    // 6) Success (IP was sent). Let the request proceed normally.
    return NGX_DECLINED;
}


//----------------------------------------------------------------------
// 11) HEALTH‐CHECK TIMER HANDLER
//     Runs every “health_interval” ms. Iterates all registered loc_confs
//     and pings their Unix socket. Toggles conf->enabled and conf->sock_fd.
//----------------------------------------------------------------------

static void
ngx_http_report_ip_health_check_handler(ngx_event_t *ev)
{
    ngx_http_report_ip_main_conf_t   *mcf;
    ngx_http_report_ip_loc_conf_t   **locs;
    ngx_uint_t                        i, n;
    ngx_http_report_ip_loc_conf_t    *conf;
    struct sockaddr_un                uaddr;
    int                               fd;
    ssize_t                           rc;
    ngx_log_t                        *log;
    ngx_msec_t                        interval;

    // ev->data was set to main_conf pointer in init_process
    mcf = ev->data;
    log = ev->log;

    // Number of registered loc_confs:
    n = mcf->loc_confs->nelts;
    locs = mcf->loc_confs->elts;
    
    for (i = 0; i < n; i++) {
        conf = locs[i];

        // Build the sockaddr_un once per iteration
        ngx_memzero(&uaddr, sizeof(struct sockaddr_un));
        uaddr.sun_family = AF_UNIX;
        ngx_memcpy(uaddr.sun_path, conf->socket_path.data, conf->socket_path.len);
        uaddr.sun_path[conf->socket_path.len] = '\0';

        if (conf->enabled && conf->sock_fd >= 0) {
            // 1) Socket was previously “alive.” Ping it with zero‐byte sendto().
            rc = sendto(conf->sock_fd,
                        (const void *) "ping", 4,
                        0,
                        (struct sockaddr *) &uaddr,
                        sizeof(struct sockaddr_un));

            if (rc < 0) {
                // Health‐check ping failure → mark dead
                ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                              "report_ip: health‐check sendto() failed, marking dead: \"%V\"",
                              &conf->socket_path);

                close(conf->sock_fd);
                conf->sock_fd = -1;
                conf->enabled = 0;
            }
            // else ping succeeded → still alive, do nothing
        }

        else {
            // 2) Either we’ve never opened OR we were previously marked dead.
            //
            //    Try to open + send a zero‐byte “ping.” If that succeeds, mark alive.
            //    If it fails, immediately close and stay dead.
            //
            fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            if (fd < 0) {
                ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                              "report_ip: health‐check socket(AF_UNIX) failed");
                continue;
            }

            rc = sendto(fd,
                        (const void *) "ping", 4,
                        0,
                        (struct sockaddr *) &uaddr,
                        sizeof(struct sockaddr_un));

            if (rc < 0) {
                // still cannot reach → stay dead
                ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                              "report_ip: health‐check failed to send, ebpf-firewall server is not working");
                close(fd);
                // conf->enabled stays 0
            }
            else {
                // health‐check succeeded → mark alive
                conf->sock_fd = fd;
                conf->enabled = 1;
            }
        }
    }

    // 3) Re‐arm the timer
    interval = mcf->health_interval;
    ngx_add_timer(ev, interval);
}


//----------------------------------------------------------------------
// 12) INIT PROCESS (per‐worker): schedule the health‐check timer
//----------------------------------------------------------------------

static ngx_int_t
ngx_http_report_ip_init_process(ngx_cycle_t *cycle)
{
    ngx_event_t                      *ev;
    ngx_http_report_ip_main_conf_t   *mcf;
    ngx_uint_t                        n;

    // Get the main_conf (set during config parsing)
    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_report_ip_module);

    // If no locations registered, no need to start a timer.
    n = (mcf->loc_confs ? mcf->loc_confs->nelts : 0);
    if (n == 0) {
        return NGX_OK;
    }

    // Allocate a single ngx_event_t from the cycle pool
    ev = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (ev == NULL) {
        return NGX_ERROR;
    }

    // Set callback, data, and log
    ev->handler = ngx_http_report_ip_health_check_handler;
    ev->data    = mcf;
    ev->log     = cycle->log;

    // Start timer for the first time
    ngx_add_timer(ev, mcf->health_interval);

    return NGX_OK;
}


//----------------------------------------------------------------------
// 13) POST‐CONFIGURATION: register the request handler in ACCESS phase
//----------------------------------------------------------------------

static ngx_int_t
ngx_http_report_ip_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    // Insert our handler into the ACCESS phase
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_report_ip_handler;
    return NGX_OK;
}
