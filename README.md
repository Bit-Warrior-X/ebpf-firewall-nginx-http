# eBPF L4 Firewall with Nginx Integration

This project implements an eBPF-based Layer 4 (L4) firewall designed to protect services, particularly Nginx, from malicious traffic. It integrates with an Nginx module that detects suspicious HTTP requests (e.g., those with unknown methods) and reports the source IP addresses to the eBPF firewall for blocking.

## Features

*   **eBPF-based L4 Filtering**: Leverages eBPF for high-performance packet filtering directly in the kernel.
*   **IP Blocking**: Dynamically blocks IP addresses reported by integrated modules.
*   **Nginx Integration**: An Nginx module (`ngx_http_report_ip_module`) identifies and reports suspicious client IPs.
*   **Configurable Block Rules**: Allows configuration of allowed and blocked IPs.
*   **Connection Tracking**: Utilizes connection tracking for stateful firewalling.
*   **Command-Line Interface (CLI)**: A userspace tool for managing the firewall.
*   **Prometheus Exporter**: Provides metrics for monitoring the firewall's activity.

## Architecture Overview

The system consists of several key components:

1.  **eBPF Kernel Module (`ebpf_firewall_kernel.c`)**: The core of the firewall, loaded into the Linux kernel. It performs L4 packet filtering based on rules managed by the userspace application, including blocking reported IP addresses.
2.  **eBPF Userspace Application (`ebpf_firewall_userspace`)**: A daemon that interacts with the eBPF kernel module. It loads the eBPF program, manages IP blocking rules (e.g., adding/removing IPs from the `blocked_ips` map), and communicates with the Nginx module via a Unix socket.
3.  **Nginx Module (`ngx_http_report_ip_module.c`)**: An Nginx HTTP module that inspects incoming HTTP requests. If a request's method is not among the configured `report_available_methods`, it extracts the client's IP address and sends it to the `ebpf_firewall_userspace` via a Unix domain socket.
4.  **Command-Line Interface (CLI) (`ebpf_firewall_cli`)**: A separate userspace tool for manual interaction with the eBPF firewall, allowing administrators to view status, add/remove IPs, etc.
5.  **Prometheus Exporter (`ebpf_firewall_prom`)**: A userspace application that exposes firewall metrics (e.g., blocked packet counts, connection statistics) in a Prometheus-compatible format for monitoring.

## Installation

### Prerequisites

Before building, ensure you have the following dependencies installed:

*   `clang` (for compiling eBPF programs)
*   `gcc` (for compiling userspace applications)
*   `make`
*   `libbpf-dev`
*   `libxdp-dev`
*   `libnetfilter-conntrack-dev`
*   `libpthread-dev`
*   `libssl-dev` (for libcrypto)
*   `libmicrohttpd-dev` (for Prometheus exporter)
*   `libprom-dev` and `libpromhttp-dev` (for Prometheus exporter)
*   Nginx source code (if you plan to compile the Nginx module with your Nginx installation)

### Building the eBPF Firewall

Navigate to the project root directory and run `make`:

```bash
make
```

This will compile the eBPF kernel object (`build/ebpf_firewall_kernel.o`), the main userspace application (`build/ebpf_firewall_userspace`), the CLI tool (`build/ebpf_firewall_cli`), and the Prometheus exporter (`build/ebpf_firewall_prom`).

### Building and Installing the Nginx Module

To integrate the Nginx module, you need to compile Nginx with the `ngx_http_report_ip_module`.

1.  Place the `ngx_http_report_ip_module.c` file (and any other necessary Nginx module source files) in a directory accessible by your Nginx source tree, for example, `nginx_http_report_ip/`.
2.  Navigate to your Nginx source directory (e.g., `/path/to/nginx`).
3.  Configure Nginx with the `--add-module` flag:

    ```bash
    ./configure --add-module=/path/to/your/nginx_http_report_ip/
    ```

    Replace `/path/to/your/nginx_http_report_ip/` with the actual path to the directory containing the Nginx module source.

4.  Compile and install Nginx:

    ```bash
    make && make install
    ```

## Configuration

### eBPF Firewall Configuration (`firewall.config`)

The `firewall.config` file (which is copied to the `build/` directory during compilation) is used to configure the eBPF userspace firewall. You may need to edit this file to define initial rules or settings. (Further details on the format and available options within `firewall.config` would require examining `ebpf_firewall_config.c` and `ebpf_firewall_config.h`.)

### Nginx Module Directives

Add the following directives to your Nginx configuration (e.g., `nginx.conf`) within the `http` or `location` blocks:

*   **`report_healthcheck_interval`**
    *   **Syntax**: `report_healthcheck_interval <milliseconds>;`
    *   **Default**: `1000` (1 second)
    *   **Context**: `http`
    *   **Description**: Sets the time interval (in milliseconds) for the Nginx module to ping the eBPF firewall's Unix socket to check its availability.

*   **`report_available_methods`**
    *   **Syntax**: `report_available_methods <METHOD1> [METHOD2 ...];`
    *   **Default**: `GET POST`
    *   **Context**: `http`, `location`
    *   **Description**: Specifies the HTTP methods that are considered valid. If an incoming request uses a method not listed here, its source IP will be reported to the eBPF firewall.

*   **`report_socket_path`**
    *   **Syntax**: `report_socket_path <path_to_unix_socket>;`
    *   **Default**: `none`
    *   **Context**: `http`, `location`
    *   **Description**: Sets the path to the Unix domain socket that the Nginx module uses to communicate with the `ebpf_firewall_userspace` application. This path must match the socket path configured in the eBPF userspace application.

#### Nginx Configuration Example:

```nginx
http {

    report_healthcheck_interval 100; #miliseconds
    report_available_methods GET POST;
    report_socket_path /tmp/unix.sock;
    
    server {
        listen  8080;

        location / {
            # Your other Nginx configurations for this location
        }
    }
}
```

## Usage

### Starting the eBPF Firewall Userspace Application

After building, you can run the main userspace application:

```bash
./build/ebpf_firewall_userspace
```

This application will load the eBPF program into the kernel and start listening on the configured Unix socket for IP blocking requests from the Nginx module.

### Using the CLI Tool

The `ebpf_firewall_cli` tool can be used to interact with the running eBPF firewall. (Specific commands and their usage would require further analysis of `ebpf_firewall_cli.c`.)

```bash
./build/ebpf_firewall_cli [commands...]
```

### Running the Prometheus Exporter

To expose firewall metrics for monitoring:

```bash
./build/ebpf_firewall_prom
```

This will start a web server (typically on port 9090, but check the source for confirmation) that Prometheus can scrape.

## How it Works

1.  An HTTP request arrives at the Nginx server.
2.  The `ngx_http_report_ip_module` intercepts the request and checks its HTTP method against the `report_available_methods` list.
3.  If the method is not allowed (e.g., an 


unknown or disallowed method), the Nginx module sends the client's IP address to the `ebpf_firewall_userspace` application via a Unix domain socket.
4.  The `ebpf_firewall_userspace` application receives the IP address and adds it to the `blocked_ips` eBPF map in the kernel.
5.  The eBPF program (`ebpf_firewall_kernel.c`) running in the kernel inspects all incoming network packets. If a packet's source IP matches an entry in the `blocked_ips` map, the packet is dropped, effectively blocking traffic from that IP address.
6.  The Nginx module periodically health-checks the Unix socket to ensure the `ebpf_firewall_userspace` is still running and responsive. If the userspace application becomes unavailable, the Nginx module will temporarily stop reporting IPs.

## Troubleshooting

*   **Nginx module not reporting IPs**: Ensure the `ebpf_firewall_userspace` application is running and the `report_socket_path` in your Nginx configuration matches the socket path used by the userspace application. Check Nginx error logs for any issues related to the `ngx_http_report_ip_module`.
*   **IPs not being blocked**: Verify that the `ebpf_firewall_userspace` application is running and has successfully loaded the `ebpf_firewall_kernel.o` program into the kernel. Check the output of the CLI tool to see if IPs are being added to the blocked list. Ensure there are no other firewall rules (e.g., `iptables`) that might be interfering.
*   **Compilation errors**: Ensure all prerequisites are installed. Check the `Makefile` for correct paths and dependencies.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues on the project's GitHub repository (if applicable).

## License

This project is licensed under the MIT License - see the `LICENSE` file for details (if available).

## Contact

For questions or support, please contact [Your Name/Email/GitHub Profile].


