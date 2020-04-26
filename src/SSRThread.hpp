#ifndef SSRTHREAD_HPP
#define SSRTHREAD_HPP
#include <QThread>

class SSRThread : public QThread
{
    Q_OBJECT
public:
    explicit SSRThread() = default;
    explicit SSRThread(int localPort, //
        int remotePort, //
        std::string local_addr, //
        std::string remote_host, //
        std::string method, //
        std::string password, //
        std::string obfs, //
        std::string obfs_param, //
        std::string protocol, //
        std::string protocol_param);
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
    std::string local_addr;
    std::string remote_host;
    std::string method;
    std::string password;
    std::string obfs;
    std::string obfs_param;
    std::string protocol;
    std::string protocol_param;
    QString inboundTag;
};
#endif // SSRTHREAD_HPP
