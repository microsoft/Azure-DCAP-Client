@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

// The below timeout is set in minutes
GLOBAL_TIMEOUT = 240

OETOOLS_REPO = "https://oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIAL_ID = "oejenkinscidockerregistry"
OETOOLS_DOCKERHUB_REPO_CREDENTIAL_ID = "oeciteamdockerhub"

def buildDockerImages() {
    node("nonSGX") {
        timeout(GLOBAL_TIMEOUT) {
            stage("Checkout") {
                cleanWs()
                checkout scm
            }
            stage("Build Ubuntu 16.04 Docker Image") {
                docker.withRegistry(OETOOLS_REPO, OETOOLS_REPO_CREDENTIAL_ID) {
                    azDcapTools1604 = oe.dockerImage("az-dcap-tools-16.04:${DOCKER_TAG}",
                                                     ".jenkins/Dockerfile",
                                                     "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=16.04")
                }
                pubazDcapTools1604 = oe.dockerImage("oeciteam/az-dcap-tools-16.04:${DOCKER_TAG}",
                                                    ".jenkins/Dockerfile",
                                                    "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=16.04")
            }
            stage("Build Ubuntu 18.04 Docker Image") {
                docker.withRegistry(OETOOLS_REPO, OETOOLS_REPO_CREDENTIAL_ID) {
                    azDcapTools1804 = oe.dockerImage("az-dcap-tools-18.04:${DOCKER_TAG}",
                                                     ".jenkins/Dockerfile",
                                                     "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=18.04")
                }
                pubazDcapTools1804 = oe.dockerImage("oeciteam/az-dcap-tools-18.04:${DOCKER_TAG}",
                                                    ".jenkins/Dockerfile",
                                                    "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=18.04")
            }
            stage("Push to OE Docker Registry") {
                docker.withRegistry(OETOOLS_REPO, OETOOLS_REPO_CREDENTIAL_ID) {
                    azDcapTools1604.push()
                    azDcapTools1804.push()
                    if(params.TAG_LATEST == true) {
                        azDcapTools1604.push('latest')
                        azDcapTools1804.push('latest')
                    }
                }
            }
            stage("Push to OE Docker Hub Registry") {
                docker.withRegistry('', OETOOLS_DOCKERHUB_REPO_CREDENTIAL_ID) {
                    pubazDcapTools1604.push()
                    pubazDcapTools1804.push()
                    if(params.TAG_LATEST == true) {
                        pubazDcapTools1604.push('latest')
                        pubazDcapTools1804.push('latest')
                    }
                }
            }
        }
    }
}

buildDockerImages()
