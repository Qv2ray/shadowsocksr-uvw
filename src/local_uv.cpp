#include "uvw_single.hpp"
#include <memory>
#include <utility>
#include <unordered_map>
#include "utils.h"
#include "sockaddr_universal.h"
#include "obfs/obfs.h"
#if defined(_WIN32)
#include <WS2tcpip.h>
#else
#include <netinet/in.h>
#endif // defined(_WIN32)
#include "shadowsocks.h"
#include "Buffer.hpp"
#include "ConnectionContext.hpp"
#include "ObfsClass.hpp"
#include "CipherEnv.hpp"
#include "LogHelper.h"

class SSRUV {
private:
    static constexpr int SVERSION = 0x05;
    std::shared_ptr<uvw::Loop> loop;
    std::shared_ptr<uvw::TimerHandle> stopTimer;
    std::shared_ptr<uvw::TCPHandle> tcpServer;
    bool isStop=false;
    profile_t profile;
    bool acl=false;
    socks5_address address;
    std::unique_ptr<ObfsClass> obfsClass;
    std::unique_ptr<CipherEnv> cipherEnv;
    uint64_t tx=0,rx=0;
    sockaddr remoteAddr;
    std::unordered_map<std::shared_ptr<uvw::TCPHandle>,std::shared_ptr<ConnectionContext>> inComingConnections;
    double last;
private:
    void stat_update_cb()
    {
        uv_timeval64_t tv;
        uv_gettimeofday(&tv);
        double now = tv.tv_sec+tv.tv_usec*1e-6;
        if (now - last > 0.5) {
            send_traffic_stat(tx, rx);
            last = now;
        }
    }
public:
    static SSRUV& getInstance()
    {
        static SSRUV instance;
        return instance;
    }
    static void stopInstance()
    {
        getInstance().stop();
    }
private:
    void stop()
    {
        isStop=true;
    }
    void handShakeReceive(const uvw::DataEvent& event,uvw::TCPHandle& client)
    {
        if(event.data[0]==0x05&&event.length>1)
        {
            auto dataWrite = std::unique_ptr<char[]>(new char[2]{ SVERSION, 0 });
            client.write(std::move(dataWrite),2);
            client.once<uvw::DataEvent>([this](auto & e,auto & h){handShakeSendCallBack(e,h);});
            return;
        }else if(event.length>1){
            auto dataWrite = std::unique_ptr<char[]>(new char[2]{ SVERSION, 0 });
            client.write(std::move(dataWrite),2);
        }
        client.close();
    }
    int server_info_head_len(char* buf_atyp_ptr){
        switch (*buf_atyp_ptr&0x7) {
        case 1:
            return 7;
        case 4:
            return 19;
        case 3:
            ++buf_atyp_ptr;
            return 4+(*buf_atyp_ptr);
        }
        return 30;//can't reach here.
    }
    void readAllAddress(uvw::DataEvent& event,uvw::TCPHandle& client)
    {
        ConnectionContext& connectionContext=*inComingConnections[client.shared_from_this()];
        Buffer& buf=*connectionContext.localBuf;
        buf.copy(event);
        if(socks5_address_parse((uint8_t*)buf.begin()+3,buf.length()-3,&address)){
            buf.drop(3);
            connectionContext.construct_obfs(*cipherEnv,*obfsClass,profile,server_info_head_len(buf.begin()+3));
            startConnect(client);
        } else {
            client.once<uvw::DataEvent>([this](auto & e,auto & h){readAllAddress(e,h);});
        }
    }
    void handShakeSendCallBack(uvw::DataEvent& event,uvw::TCPHandle& client)
    {
        int cmd=0;
        ConnectionContext& connectionContext=*inComingConnections[client.shared_from_this()];
        Buffer& buf=*connectionContext.localBuf;
        if(buf.length()+event.length>=5){
            //VER 	CMD 	RSV 	ATYP 	DST.ADDR 	DST.PORT
            //1 	1 	    0x00 	1 	      动态 	     2
            switch (buf.length()) {
            case 0:
                cmd = event.data[1];
                break;
            case 1:
                cmd=event.data[0];
                break;
            default:
                cmd=buf[1];
                break;
            }
            buf.copy(event);//buf never equal to zero
            switch (cmd) {
            case 0x01:
                if(buf.length()!=0&&socks5_address_parse((uint8_t*)buf.begin()+3,buf.length()-3,&address)){
                    buf.drop(3);
                    connectionContext.construct_obfs(*cipherEnv,*obfsClass,profile,server_info_head_len(buf.begin()+3));
                    startConnect(client);
                } else {
                    client.once<uvw::DataEvent>([this](auto & e,auto & h){readAllAddress(e,h);});
                    return;
                }
                break;
            case 0x03:
                //todo udp assc
                break;
            case 0x02:
            default:
                client.close();
                break;
            }
        }else {
            //shall we just close it?
            buf.copy(event);
            client.once<uvw::DataEvent>([this](auto & e,auto & h){handShakeSendCallBack(e,h);});
        }
    }
    void panic(std::shared_ptr<uvw::TCPHandle> clientConnection)
    {
        LOGE("panic close client connection");
        if(inComingConnections.find(clientConnection)!=inComingConnections.end())
        {
            auto ctxPtr=inComingConnections[clientConnection];
            inComingConnections.erase(clientConnection);
            ctxPtr->client->clear();
            ctxPtr->client->close();
            if(ctxPtr->remote)
            {
                ctxPtr->remote->clear();
                ctxPtr->remote->close();
            }
        }
    }
    int insertSSRHeader(ConnectionContext&ctx,Buffer&buf)
    {
        tx+=buf.length();
        buf.protocolPluginPreEncrypt(*obfsClass,ctx);
        int err=buf.ssEncrypt(*cipherEnv,ctx);
        if(err)
        {
            return err;
        }
        buf.clientEncode(*obfsClass,ctx);
        return 0;
    }
    void sockStream(uvw::DataEvent& event,uvw::TCPHandle& client)
    {
        if(client.closing()) return;
        auto clientPtr=client.shared_from_this();
        if(inComingConnections.find(clientPtr)==inComingConnections.end())
        {
            return;
        }
        auto connectionContextPtr=inComingConnections[clientPtr];
        auto& connectionContext=*connectionContextPtr;
        Buffer& buf=*connectionContext.remoteBuf;
        buf.copy(event);
        int err = insertSSRHeader(connectionContext,buf);
        if(err)
        {
            panic(clientPtr);
            return;
        }
        if(buf.length()!=0)
        {
            connectionContext.remote->once<uvw::WriteEvent>([clientPtr,this](const auto&,uvw::TCPHandle&h){
                auto& connectionContext=*inComingConnections[clientPtr];
                Buffer& buf=*connectionContext.remoteBuf;
                buf.clear();
                h.read();
            });
            connectionContext.remote->write(buf.begin(),buf.length());
            buf.clear();
            return;
        }
        else
        {
            clientPtr->stop();
        }
    }
    void remoteRecv(ConnectionContext& ctx,uvw::DataEvent& event,uvw::TCPHandle& remote)
    {
        if(remote.closing())
        {
            return;
        }
        rx += event.length;
        auto& buf=*ctx.localBuf;
        char* base=event.data.get();
        char* guard=base+event.length;
        for(auto iter=base;iter<guard;iter+=Buffer::BUF_DEFAULT_CAPACITY)
        {
            buf.bufRealloc(Buffer::BUF_DEFAULT_CAPACITY);
            size_t remain=guard-iter;
            size_t len = remain>Buffer::BUF_DEFAULT_CAPACITY?Buffer::BUF_DEFAULT_CAPACITY:remain;
            buf.copyFromBegin(iter,len);
            int needsendback=buf.clientDecode(*obfsClass,ctx);
            if(needsendback)
            {
                ctx.remoteBuf->clientEncode(*obfsClass,ctx,0);
                remote.once<uvw::WriteEvent>([&ctx](auto&,auto&){ctx.remoteBuf->clear();ctx.client->read();});
                remote.write(ctx.remoteBuf->begin(),ctx.remoteBuf->length());
            }
            if(buf.length()>0)
            {
                int err=buf.ssDecrypt(*cipherEnv,ctx);
                if(err)
                {
                    panic(ctx.client);
                    return;
                }
            }
            if(buf.length()!=0)
            {
                buf.protocolPluginPostDecrypt(*obfsClass,ctx);
            }
            if(static_cast<int>(buf.length())<0){
                panic(ctx.client);
                return;
            }
            if(buf.length()==0)
            {
                continue;
            }
            ctx.client->write(buf.duplicateDataToArray(),buf.length());
            buf.clear();
        }
    }

    void connectRemote(ConnectionContext& ctx)
    {
        auto remote=ctx.remote;
        if(!remote) return;
        remote->connect(remoteAddr);
        remote->on<uvw::DataEvent>([&ctx,this](uvw::DataEvent& event,uvw::TCPHandle& remoteHandle){
            remoteRecv(ctx,event,remoteHandle);
        });
        remote->once<uvw::ConnectEvent>([&ctx,this](const uvw::ConnectEvent &, uvw::TCPHandle &h) {
            h.read();
            ctx.client->write(std::unique_ptr<char[]>(new char[10]{  5, 0, 0, 1, 0, 0, 0, 0, 0, 0}),10);
            ctx.remoteBuf.reset(new Buffer);
            ctx.remoteBuf->copy(*ctx.localBuf);
            ctx.localBuf->clear();
            int err=insertSSRHeader(ctx,*ctx.remoteBuf);
            if(err)
            {
                panic(ctx.client);
                return;
            }
            ctx.remote->once<uvw::WriteEvent>([&ctx,this](auto&,auto&){
                ctx.client->on<uvw::DataEvent>([this](uvw::DataEvent&event,uvw::TCPHandle&client) {
                    //when this event traiggered, we are in stream mode.
                    sockStream(event,client);
                });
                ctx.remoteBuf->clear();
            });
            ctx.remote->write(ctx.remoteBuf.get()->begin(),ctx.remoteBuf.get()->length());
            //stop remote send and start local recv
        });
    }
    void startConnect(uvw::TCPHandle& client)
    {
        auto clientPtr=client.shared_from_this();
        auto& connectionContext=*inComingConnections[clientPtr];
        if(acl){
            //todo acl
        }
        auto remoteTcp = loop->resource<uvw::TCPHandle>();
        connectionContext.setRemoteTcpHandle(remoteTcp);
        //todo timer
        remoteTcp->once<uvw::ErrorEvent>([clientPtr,this](const uvw::ErrorEvent &e, uvw::TCPHandle &) {
            LOGE("remote error %s",e.what());
            panic(clientPtr); });
        remoteTcp->once<uvw::CloseEvent>([clientPtr,this](const uvw::CloseEvent &, uvw::TCPHandle &) {
            LOGI("remote close");
            panic(clientPtr);
        });
        remoteTcp->once<uvw::EndEvent>([clientPtr,this](const uvw::EndEvent &, uvw::TCPHandle &) {
            LOGI("remote end event");
            panic(clientPtr);
        });
        remoteTcp->noDelay(true);
        //fastopen is not implemented due to fastopen is still WIP https://github.com/libuv/libuv/pull/1136
        connectRemote(connectionContext);
        //we send socks5 fake response after we real connected remote server;
    }
    void listen(uvw::Loop &loop) {
        tcpServer = loop.resource<uvw::TCPHandle>();
        tcpServer->noDelay(true);
        tcpServer->on<uvw::ListenEvent>([this](const uvw::ListenEvent &, uvw::TCPHandle &srv) {
            std::shared_ptr<uvw::TCPHandle> client = srv.loop().resource<uvw::TCPHandle>();
            inComingConnections.emplace(std::make_pair(client,std::shared_ptr<ConnectionContext>{new ConnectionContext{client,obfsClass.get(),cipherEnv.get()}}));
            client->once<uvw::CloseEvent>([this](const uvw::CloseEvent &, uvw::TCPHandle &c) {
                auto clientPtr=c.shared_from_this();
                LOGI("client close");
                panic(clientPtr); });
            client->once<uvw::ErrorEvent>([this](const uvw::ErrorEvent&e, uvw::TCPHandle &c) {
                auto clientPtr=c.shared_from_this();
                LOGE("client error %s",e.what());
                panic(clientPtr); });
            client->once<uvw::DataEvent>([this](const uvw::DataEvent& event,uvw::TCPHandle &client){
                handShakeReceive(event,client);
            });
            srv.accept(*client);
            client->read();
        });

        tcpServer->bind(profile.local_addr, profile.local_port);
        tcpServer->listen();
    }
public:
    int loopMain(profile_t& p)
    {
        profile=p;
        isStop=false;
        loop = uvw::Loop::create();
        signal(SIGPIPE,SIG_IGN);
        stopTimer=loop->resource<uvw::TimerHandle>();
        LOGI("listening at %s:%d",profile.local_addr,profile.local_port);
        obfsClass.reset(new ObfsClass{profile.protocol,profile.obfs});
        LOGI("initializing ciphers...%s",profile.method);
        cipherEnv.reset(new CipherEnv{profile.password,profile.method});
        stopTimer->on<uvw::TimerEvent>([this](auto&,auto& handle){
           if(isStop)
           {
               handle.stop();
               handle.close();
               tcpServer->close();
               inComingConnections.clear();
               loop->clear();
               loop->close();
               obfsClass.reset(nullptr);
               cipherEnv.reset(nullptr);
               loop->stop();
           }
        });
        stopTimer->start(uvw::TimerHandle::Time{500},uvw::TimerHandle::Time{500});
        auto getAddrInfoReq=loop->resource<uvw::GetAddrInfoReq>();
        char digitBuffer[20]={0};
        sprintf(digitBuffer,"%d",profile.remote_port);
        auto dns_res=getAddrInfoReq->addrInfoSync(profile.remote_host,digitBuffer);
        if(dns_res.first){
           remoteAddr=*dns_res.second->ai_addr;
        } else{
            return -1;//dns not resolved
        }
        listen(*loop);
        loop->run();
        return 0;
    }
private:
    SSRUV()=default;
};
int
start_ssr_uv_local_server(profile_t profile)
{
    auto& ssr=SSRUV::getInstance();
    ssr.loopMain(profile);
    return 0;
}

int stop_ss_local_server()
{
    SSRUV::stopInstance();
    return 0;
}
