#ifndef SSRTHREAD_HPP
#define SSRTHREAD_HPP
#include <QThread>

class SSRThread : public QThread
{
    Q_OBJECT
public:
    enum class SSR_WORK_MODE{TCP_ONLY=0,UDP_ONLY=1};
    explicit SSRThread() = default;
    explicit SSRThread(int localPort,
        int remotePort,
        std::string local_addr,
        std::string remote_host,
        std::string method,
        std::string password,
        std::string obfs,
        std::string obfs_param,
        std::string protocol,
        std::string protocol_param);
    explicit SSRThread(int localPort,
                       int remotePort,
                       int timeout,
                       int mtu,
                       SSR_WORK_MODE mode,
                       std::string local_addr,
                       std::string remote_host,
                       std::string method,
                       std::string password,
                       std::string obfs,
                       std::string obfs_param,
                       std::string protocol,
                       std::string protocol_param,
         int verbose=0
        );
    ~SSRThread() override;
signals:
    void OnDataReady(quint64 dataUp, quint64 dataDown);
    void onSSRThreadLog(QString);

protected:
    void run() override;

public slots:
    void stop();

private:
    int localPort = 0;
    int remotePort = 0;
    int timeout = 60000;//ms
    int mtu = 0;
    int mode = 0;
    std::string local_addr;
    std::string remote_host;
    std::string method;
    std::string password;
    std::string obfs;
    std::string obfs_param;
    std::string protocol;
    std::string protocol_param;
    int verbose = 0;
    QString inboundTag;
};
#endif // SSRTHREAD_HPP
