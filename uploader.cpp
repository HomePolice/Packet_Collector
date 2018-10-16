#include <string>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <time.h>
#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/core/utils/memory/stl/AWSStringStream.h>

using namespace std;
using namespace Aws;
using namespace Aws::S3;
using namespace Aws::S3::Model;

int upload(char *argv[]);

int main(int argc, char *argv[])
{
    // 생각보다 정상적인 상황에서 전송 실패가 자주 발생하므로 성공시 까지 계속 전송하도록 설계
    while (true)
    {
        if (upload(argv) == 0)
        {
            break;
        }
        usleep(1000);
    }
}

int upload(char *argv[])
{
    // aws sdk 초기화
    Aws::SDKOptions options;
    Aws::InitAPI(options);

    // 현재 경로
    char curDir[1000];

    // 현재 시간
    time_t     now = time(NULL);
    struct tm  *tstruct;
    char       buf[80];
    tstruct = localtime(&now);
    char label[200] = "/";
    strcat(label, argv[2]);
    strftime(buf, sizeof(buf), "/json/%Y-%m-%d.%X.json", tstruct);
    strcat(label, buf);
    cout << label << endl;
 
    // aws에 입력할 기본 정보
    String KEY = label;   // s3에 저장될 파일의 이름
    const String BUCKET = "homepolice"; // S3 BUCKET의 이름
    const String fileName = argv[1];    // 전송할 LOCAL 파일의 이름

    // 함수에 파라미터로 full path가 들어가야 해서 full path로 가공
    getcwd(curDir, 1000);
    strcat(curDir, "/");
    strcat(curDir, argv[1]);
    cout << curDir << endl;

    // aws 연결 초기화, 지역 등 설정
    Client::ClientConfiguration config;
    config.region = Region::AP_NORTHEAST_2;
    config.scheme = Http::Scheme::HTTPS;

    // 연결
    S3Client s3Client(Auth::AWSCredentials("id", "password"), config);

    // 전송 담당 객체 생성
    PutObjectRequest putObjectRequest;
    putObjectRequest.WithBucket(BUCKET).WithKey(KEY);

    // 전송 내용을 가공하여 내용을 채움
    auto requestStream = MakeShared<FStream>("PutObjectInputStream", fileName.c_str(), ios_base::in | ios_base::binary);
    putObjectRequest.SetBody(requestStream);
    // 전송
    auto putObjectOutcome = s3Client.PutObject(putObjectRequest);
    // 결과 확인
    if (putObjectOutcome.IsSuccess())
    {
        cout << "\n\nPut object success \n\n" << endl;
        // 성공했으면 전송한 파일을 삭제합니다.
        int result = remove(curDir);
        cout << errno << endl;
        Aws::ShutdownAPI(options);
        return 0;
    }
    else
    {
        cout << "\n\nError while putting Object \n\n" << putObjectOutcome.GetError().GetExceptionName() <<
            " " << putObjectOutcome.GetError().GetMessage() << endl;
        Aws::ShutdownAPI(options);
        return 1;
    }
}
