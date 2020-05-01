#include "getopt.h"
#include "shadowsocksr.h"
#include "ssrutils.h"
#include "signal.h"


static void usage()
{
    printf("\n");
    printf("shadowsocks-uvw \n\n");
    printf(
        "  maintained by DuckVador <Lx3JQkmzRS@protonmail.com>\n\n");
    printf("  usage:\n\n");
    printf("    ssr-local\n");
    printf("\n");
    printf(
        "       -s <server_host>           Host name or IP address of your remote server.\n");
    printf(
        "       -p <server_port>           Port number of your remote server.\n");
    printf(
        "       -b <local_address>         Local address to bind.\n");
    printf(
        "       -l <local_port>            Port number of your local server.\n");
    printf(
        "       -k <password>              Password of your remote server.\n");
    printf(
        "       -m <encrypt_method>        Encrypt method: none, table, rc4, rc4-md5,\n");
    printf(
        "                                  aes-128-cfb, aes-192-cfb, aes-256-cfb,\n");
    printf(
        "                                  aes-128-ctr, aes-192-ctr, aes-256-ctr,\n");
    printf(
        "                                  bf-cfb, camellia-128-cfb, camellia-192-cfb,\n");
    printf(
        "                                  camellia-256-cfb, cast5-cfb, des-cfb,\n");
    printf(
        "                                  idea-cfb, rc2-cfb, seed-cfb, salsa20,\n");
    printf(
        "                                  chacha20 and chacha20-ietf.\n");
    printf(
        "                                  The default cipher is rc4-md5.\n");
    printf("\n");
    printf(
        "       [-t <timeout>]             Socket timeout in seconds.\n");
    printf("\n");
    printf(
        "       [-O <protocol>]            protocol: origin, auth_sha1, auth_sha1_v2, auth_sha1_v4,\n");
    printf(
        "                                  auth_aes_128_sha1, auth_aes_128_md5, auth_chain_a, auth_chain_b,\n");
    printf(
        "                                  auth_chain_c, auth_chain_d, auth_chain_e, auth_chain_f.\n");
    printf("\n");
    printf(
        "       [-G <protocol parameter>]  Parameter of your protocol.\n");
    printf(
        "       [-o <obfs>]                obfs: plain, http_simple, http_post, tls1.2_ticket_auth.\n");
    printf("\n");
    printf(
        "       [-g <obfs parameter>]      Parameter of your obfs.\n");
    printf(
        "       [-u]                       Enable UDP relay.\n");
    //    printf(
    //        "       [-U]                       Enable UDP relay and disable TCP relay.\n");
    printf("\n");
    printf(
        "       [--mtu <MTU>]              MTU of your network interface.\n");
    printf("\n");
    printf(
        "       [-v]                       Verbose mode.\n");
    printf(
        "       [-h, --help]               Print this message.\n");
    printf("\n");
}
void sigintHandler(int sig_num)
{
    /* Reset handler to catch SIGINT next time.
       Refer http://en.cppreference.com/w/c/program/signal */
    signal(SIGINT, sigintHandler);
    stop_ssr_uv_local_server();
    printf("\n Waiting main loop to exit\n");
    fflush(stdout);
}

int main(int argc, char** argv)
{
    int c;
    int option_index = 0;
    profile_t p {};
    p.method = "rc4-md5";
    p.local_addr = "0.0.0.0";
    p.remote_host = "127.0.0.1";
    p.remote_port = 0;
    p.timeout = 60000;
    p.mtu = 1500;
    p.obfs = "origin";
    p.obfs_param = "";
    p.protocol = "plain";
    p.protocol_param = "";
    p.password = "shadowsocksr-uvw";
    opterr = 0;
    static struct option long_options[] = {
        { "mtu", required_argument, 0, 0 },
        { "help", no_argument, 0, 0 },
        { "host", required_argument, 0, 0 },
        { 0, 0, 0, 0 }
    };
    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:i:c:b:L:a:n:huUvA6"
                                        "O:o:G:g:",
                long_options, &option_index))
        != -1) {
        switch (c) {
        case 0:
            if (option_index == 0) {
                p.mtu = atoi(optarg);
                LOGI("set MTU to %d", p.mtu);
            } else if (option_index == 1) {
                usage();
                exit(EXIT_SUCCESS);
            } else if (option_index == 2) {
                p.remote_host = optarg;
            }
            break;
        case 's':
            p.remote_host = optarg;
            break;
        case 'p':
            p.remote_port = atoi(optarg);
            break;
        case 'l':
            p.local_port = atoi(optarg);
            break;
        case 'k':
            p.password = optarg;
            break;
        case 't':
            p.timeout = atoi(optarg) * 1000;
            break;
        case 'O':
            p.protocol = optarg;
            break;
        case 'm':
            p.method = optarg;
            break;
        case 'o':
            p.obfs = optarg;
            break;
        case 'G':
            p.protocol_param = optarg;
            break;
        case 'g':
            p.obfs_param = optarg;
            break;
        case 'b':
            p.local_addr = optarg;
            break;
        case 'u':
            p.mode = 1;
            break;
        case 'v':
            p.verbose = 1;
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case '?':
            // The option character is not recognized.
            LOGE("Unrecognized option: %s", optarg);
            opterr = 1;
            break;
        }
    }
    if (p.local_port==0 || p.remote_port == 0)
    {
        opterr = 1;
    }
    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }
    signal(SIGINT,sigintHandler);
    start_ssr_uv_local_server(p);
    return 0;
}
