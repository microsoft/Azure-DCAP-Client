@Library("OpenEnclaveCommon") _
oe = new jenkins.common.Openenclave()

OETOOLS_REPO = "https://oejenkinscidockerregistry.azurecr.io"
OETOOLS_REPO_CREDENTIAL_ID = "oejenkinscidockerregistry"

def buildDockerImages() {
    node("nonSGX") {
        stage("Checkout") {
            cleanWs()
            checkout scm
        }
        docker.withRegistry(OETOOLS_REPO, OETOOLS_REPO_CREDENTIAL_ID) {
            stage("Build Ubuntu 16.04 Docker Image") {
                azDcapTools1604 = oe.dockerImage("az-dcap-tools-16.04:${DOCKER_TAG}",
                                                 ".jenkins/Dockerfile",
                                                 "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=16.04")
            }
            stage("Build Ubuntu 18.04 Docker Image") {
                azDcapTools1804 = oe.dockerImage("az-dcap-tools-18.04:${DOCKER_TAG}",
                                                 ".jenkins/Dockerfile",
                                                 "--build-arg UNAME=\$(id -un) --build-arg ubuntu_version=18.04")
            }
            stage("Push to OE Docker Registry") {
                azDcapTools1604.push()
                azDcapTools1804.push()
                if(params.TAG_LATEST == true) {
                    azDcapTools1604.push('latest')
                    azDcapTools1804.push('latest')
                }
            }
        }
    }
}

buildDockerImages()
