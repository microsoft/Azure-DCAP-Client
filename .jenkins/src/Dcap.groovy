#!/usr/bin/groovy
// Licensed under the MIT License.

String dockerBuildArgs(String... args) {
    String argumentString = ""
    for(arg in args) {
        argumentString += " --build-arg ${arg}"
    }
    return argumentString
}

String dockerImage(String tag, String dockerfile = ".jenkins/Dockerfile", String buildArgs = "") {
    return docker.build(tag, "${buildArgs} -f ${dockerfile} .")
}

def ContainerRun(String imageName, String compiler, String task, String runArgs="") {
    exec_with_retry(10,300){
        docker.withRegistry("https://dcapdockerciregistry.azurecr.io", "dcapdockerciregistry") {
            def image = docker.image(imageName)
            image.pull()
            image.inside(runArgs) {
                dir("${WORKSPACE}/build") {
                    Run(compiler, task)
                }
            }
        }
    }
}

def azureEnvironment(String task, String imageName = "oetools-deploy:latest") {
    withCredentials([usernamePassword(credentialsId: 'SERVICE_PRINCIPAL_OSTCLAB',
                                      passwordVariable: 'SERVICE_PRINCIPAL_PASSWORD',
                                      usernameVariable: 'SERVICE_PRINCIPAL_ID'),
                     string(credentialsId: 'OSCTLabSubID', variable: 'SUBSCRIPTION_ID'),
                     string(credentialsId: 'TenantID', variable: 'TENANT_ID')]) {
        docker.withRegistry("https://oejenkinscidockerregistry.azurecr.io", "oejenkinscidockerregistry") {
            def image = docker.image(imageName)
            image.pull()
            image.inside {
                sh """#!/usr/bin/env bash
                      set -o errexit
                      set -o pipefail
                      source /etc/profile
                      ${task}
                   """
            }
        }
    }
}

def runTask(String task) {
    dir("${WORKSPACE}/build") {
        sh """#!/usr/bin/env bash
                set -o errexit
                set -o pipefail
                source /etc/profile
                ${task}
            """
    }
}

def Run(String compiler, String task, String compiler_version = "") {
    def c_compiler
    def cpp_compiler
    switch(compiler) {
        case "cross":
            // In this case, the compiler is set by the CMake toolchain file. As
            // such, it is not necessary to specify anything in the environment.
            runTask(task)
            return
        case "clang":
            c_compiler = "clang"
            cpp_compiler = "clang++"
            break
        case "gcc":
            c_compiler = "gcc"
            cpp_compiler = "g++"
            break
        default:
            // This is needed for backwards compatibility with the old
            // implementation of the method.
            c_compiler = "clang"
            cpp_compiler = "clang++"
            compiler_version = "7"
    }
    if (compiler_version) {
        c_compiler += "-${compiler_version}"
        cpp_compiler += "-${compiler_version}"
    }
    withEnv(["CC=${c_compiler}","CXX=${cpp_compiler}"]) {
        runTask(task);
    }
}

def deleteRG(List resourceGroups, String imageName = "oetools-deploy:latest") {
    stage("Delete ${resourceGroups.toString()} resource groups") {
        resourceGroups.each { rg ->
            withEnv(["RESOURCE_GROUP=${rg}"]) {
                dir("${WORKSPACE}/.jenkins/provision") {
                    azureEnvironment("./cleanup.sh", imageName)
                }
            }
        }
    }
}

def emailJobStatus(String status) {
    emailext (
      to: '$DEFAULT_RECIPIENTS',      
      subject: "[Jenkins Job ${status}] ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
      body: """            
            <p>               
            For additional logging details for this job please check: 
            <a href="${env.BUILD_URL}">${env.JOB_NAME} - ${env.BUILD_NUMBER}</a>
            </p>
            """,
      recipientProviders: [[$class: 'DevelopersRecipientProvider'], [$class: 'RequesterRecipientProvider']],
      mimeType: 'text/html'     
    )
}

/**
 * Compile open-enclave on Windows platform, generate NuGet package out of it, 
 * install the generated NuGet package, and run samples tests against the installation.
 */
def WinCompilePackageTest(String dirName, String buildType, String hasQuoteProvider, Integer timeoutSeconds, String lviMitigation = 'None', String lviMitigationSkipTests = 'ON') {
    cleanWs()
    checkout scm
    dir(dirName) {
        bat """
            vcvars64.bat x64 && \
            cmake.exe ${WORKSPACE} -G Ninja -DCMAKE_BUILD_TYPE=${buildType} -DBUILD_ENCLAVES=ON -DHAS_QUOTE_PROVIDER=${hasQuoteProvider} -DLVI_MITIGATION=${lviMitigation} -DLVI_MITIGATION_SKIP_TESTS=${lviMitigationSkipTests} -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCPACK_GENERATOR=NuGet -Wdev && \
            ninja.exe && \
            ctest.exe -V -C ${buildType} --timeout ${timeoutSeconds} && \
            cpack.exe -D CPACK_NUGET_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY && \
            cpack.exe && \
            (if exist C:\\oe rmdir /s/q C:\\oe) && \
            nuget.exe install open-enclave -Source %cd% -OutputDirectory C:\\oe -ExcludeVersion && \
            set CMAKE_PREFIX_PATH=C:\\oe\\open-enclave\\openenclave\\lib\\openenclave\\cmake && \
            cd C:\\oe\\open-enclave\\openenclave\\share\\openenclave\\samples && \
            setlocal enabledelayedexpansion && \
            for /d %%i in (*) do (
                cd C:\\oe\\open-enclave\\openenclave\\share\\openenclave\\samples\\"%%i"
                mkdir build
                cd build
                cmake .. -G Ninja -DNUGET_PACKAGE_PATH=C:\\oe_prereqs -DLVI_MITIGATION=${lviMitigation} || exit /b %errorlevel%
                ninja || exit /b %errorlevel%
                ninja run || exit /b %errorlevel%
            )
            """
    }
}

def exec_with_retry(int max_retries = 10, int retry_timeout = 30, Closure body) {
    int retry_count = 1
    while (retry_count <= max_retries) {
        try {
            body.call()
            break
        } catch (Exception e) {
            if (retry_count == max_retries) {
                throw e
            }
            println("Command failed. Retry count ${retry_count}/${max_retries}. Retrying in ${retry_timeout} seconds")
            sleep(retry_timeout)
            retry_count += 1
            continue
        }
    }
}

return this