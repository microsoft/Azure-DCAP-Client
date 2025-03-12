#include "stdafx.h"
#include "CppUnitTest.h"
#include "curl_easy.h"
#include <private.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

static void DefaultLogCallback(sgx_ql_log_level_t level, const char* message)
{
    std::string output("Azure Quote Provider: libdcap_quoteprov [");
    if (level == SGX_QL_LOG_ERROR)
    {
        output += "ERROR";
    }
    else if (level == SGX_QL_LOG_INFO)
    {
        output += "INFO";
    }
    output += "]: ";
    output += message;
    Logger::WriteMessage(output.c_str());
}

TEST_MODULE_INITIALIZE(InitializeModule)
{
    logger_function = DefaultLogCallback;
    logger_callback = DefaultLogCallback;
}

namespace dcap_provider_tests
{
    TEST_CLASS(Curl_EasyTests)
    {
    public:
        
        TEST_METHOD(TestCreateCurlEasy)
        {
            auto curl = curl_easy::create("http://www.microsoft.com", nullptr);
            Assert::IsTrue(static_cast<bool>(curl), L"Create curl_easy object.");
        }

        TEST_METHOD(TestSimpleNetworkExchanges)
        {
            {
                auto curl =
                    curl_easy::create("https://www.microsoft.com", nullptr);
                Assert::IsTrue(
                    static_cast<bool>(curl), L"Create curl_easy object.");

                curl->perform();
            }
            {
                auto curl =
                    curl_easy::create("https://www.example.com", nullptr);
                Assert::IsTrue(
                    static_cast<bool>(curl), L"Create curl_easy object.");

                curl->perform();
            }
            {
                auto curl = curl_easy::create(
                    "https://www.nonexistanthost.com", nullptr);
                Assert::IsTrue(
                    static_cast<bool>(curl), L"Create curl_easy object.");

                Assert::ExpectException<curl_easy::error>(
                    [&] { curl->perform(); });

            }

        }

        TEST_METHOD(GetHeader)
        {
            auto curl = curl_easy::create("https://www.microsoft.com", nullptr);
            Assert::IsTrue(
                static_cast<bool>(curl), L"Create curl_easy object.");

            curl->perform();

            const std::string *contentType = curl->get_header("Content-Type");
            Assert::IsNotNull(contentType);

            Assert::AreNotEqual(
                std::string::npos,
                contentType->find("text/html"));

            contentType = curl->get_header("BogusHeaderName");
            Assert::IsNull(contentType);

        }

    };
}