// The below timeout is set in minutes
GLOBAL_TIMEOUT = 240

DCAPTOOLS_REPO = "https://dcapdockerciregistry.azurecr.io"
DCAPTOOLS_REPO_CREDENTIAL_ID = "dcapdockerciregistry"

def buildDockerImages() {
    node("nonSGX") {
        timeout(GLOBAL_TIMEOUT) {
            stage("Checkout") {
                cleanWs()
                checkout scm
            }
            def dcap = load pwd() + "/.jenkins/src/Dcap.groovy"
            parallel "Build Ubuntu 18.04 Docker Image": {
                stage("Build Ubuntu 18.04 Docker Image") {
                    azDcapTools1804 = dcap.dockerImage("dcapdockerciregistry-ubuntu18.04:${DOCKER_TAG}",
                                                        ".jenkins/Dockerfile",
                                                        "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=18.04")
                    pubazDcapTools1804 = dcap.dockerImage("dcapdockerciregistry/dcapdockerciregistry-ubuntu18.04:${DOCKER_TAG}",
                                                        ".jenkins/Dockerfile",
                                                        "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=18.04")
                }
            },"Build Ubuntu 20.04 Docker Image":{
                stage("Build Ubuntu 20.04 Docker Image") {
                    azDcapTools2004 = dcap.dockerImage("dcapdockerciregistry-ubuntu20.04:${DOCKER_TAG}",
                                                        ".jenkins/Dockerfile",
                                                        "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=20.04"
                    pubazDcapTools2004 = dcap.dockerImage("dcapdockerciregistry/dcapdockerciregistry-ubuntu20.04:${DOCKER_TAG}",
                                                        ".jenkins/Dockerfile",
                                                        "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=20.04")
                }
            },
            ,"Build Ubuntu 22.04 Docker Image":{
                stage("Build Ubuntu 22.04 Docker Image") {
                    azDcapTools2204 = dcap.dockerImage("dcapdockerciregistry-ubuntu22.04:${DOCKER_TAG}",
                                                        ".jenkins/Dockerfile",
                                                        "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=22.04"
                    pubazDcapTools2204 = dcap.dockerImage("dcapdockerciregistry/dcapdockerciregistry-ubuntu22.04:${DOCKER_TAG}",
                                                        ".jenkins/Dockerfile",
                                                        "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=22.04")
                }
            }
            stage("Push to DCAP Docker Registry") {
                docker.withRegistry(DCAPTOOLS_REPO, DCAPTOOLS_REPO_CREDENTIAL_ID) {
                    azDcapTools1804.push()
                    azDcapTools2004.push()
                    azDcapTools2204.push()
                    if(params.TAG_LATEST == true) {
                        azDcapTools1804.push('latest')
                        azDcapTools2004.push('latest')
                        azDcapTools2204.push('latest')
                    }
                }
            }
        }
    }
}
buildDockerImages()
