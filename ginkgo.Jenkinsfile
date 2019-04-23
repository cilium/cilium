@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        MEMORY = "4096"
        SERVER_BOX = "cilium/ubuntu"
        NETNEXT=setIfLabel("ci/net-next", "true", "false")
    }

    options {
        timeout(time: 240, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Checkout') {
            options {
                timeout(time: 10, unit: 'MINUTES')
            }

            steps {
                BuildIfLabel('area/k8s', 'Cilium-PR-Kubernetes-Upstream')
                BuildIfLabel('integration/cni-flannel', 'Cilium-PR-K8s-Flannel')
                BuildIfLabel('area/k8s', 'Cilium-PR-Ginkgo-Tests-K8s')
                BuildIfLabel('area/documentation', 'Cilium-PR-Doc-Tests')
                sh 'env'
                checkout scm
                sh 'mkdir -p ${PROJ_PATH}'
                sh 'ls -A | grep -v src | xargs mv -t ${PROJ_PATH}'
                sh '/usr/local/bin/cleanup || true'
            }
        }
        stage('Precheck') {
            options {
                timeout(time: 20, unit: 'MINUTES')
            }

            environment {
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/"
            }
            steps {
               sh "cd ${TESTDIR}; make jenkins-precheck"
            }
            post {
               always {
                   sh "cd ${TESTDIR}; make clean-jenkins-precheck || true"
               }
            }
        }
        stage ("copy-code-and-boot-vms"){
            options {
                timeout(time: 30, unit: 'MINUTES')
            }

            environment {
                FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
            }
            parallel {
                stage('boot-vms-runtime') {
                    environment {
                        GOPATH="${WORKSPACE}/runtime-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        sh 'cd ${TESTDIR}; vagrant up runtime --provision'
                    }
                    post {
                        failure {
                            script {
                                if  (currentBuild.description == '') {
                                    currentBuild.description = 'runtime vm provisioning fail'
                                }
                            }
                        }
                    }
                }
                stage('boot-vms-K8s-1.10-net-next') {
                    environment {
                        GOPATH="${WORKSPACE}/k8s-lower-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
						NETNEXT="true"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.10 vagrant up k8s1-1.10 k8s2-1.10 --provision'
                    }
                    post {
                        failure {
                            script {
                                if  (currentBuild.description == '') {
                                    currentBuild.description = 'K8s 1.10 net-next vm provisioning fail'
                                }
                            }
                        }
                    }
                }
                stage('boot-vms-K8s-1.14') {
                    environment {
                        GOPATH="${WORKSPACE}/k8s-higher-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.14 vagrant up k8s1-1.14 k8s2-1.14 --provision'
                    }
                    post {
                        failure {
                            script {
                                if  (currentBuild.description == '') {
                                    currentBuild.description = 'K8s 1.14 vm provisioning fail'
                                }
                            }
                        }
                    }
                }
            }
        }
        stage ("BDD-Test-PR"){
            options {
                timeout(time: 110, unit: 'MINUTES')
            }
            environment {
                FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
            }
            failFast true
            parallel {
                stage('BDD-Test-PR-runtime') {
                    environment {
                        GOPATH="${WORKSPACE}/runtime-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; ginkgo --focus=" Runtime*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                    }
                    post {
                        always {
                            sh 'cd ${TESTDIR}; ./post_build_agent.sh || true'
                            sh 'cd ${TESTDIR}; ./archive_test_results.sh || true'
                            sh 'cd ${TESTDIR}/..; mv *.zip ${WORKSPACE} || true'
                            sh 'cd ${TESTDIR}; mv *.xml ${WORKSPACE}/${PROJ_PATH}/test || true'
                            sh 'cd ${TESTDIR}; vagrant destroy -f || true'
                        }
                        failure {
                            script {
                                if  (currentBuild.description == '') {
                                    currentBuild.description = 'Runtime tests fail'
                                }
                            }
                        }
                    }
                }
                stage('BDD-Test-PR-K8s-1.10-net-next') {
                    environment {
                        GOPATH="${WORKSPACE}/k8s-lower-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
						NETNEXT="true"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.10 ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                    }
                    post {
                        always {
                            sh 'cd ${TESTDIR}; ./post_build_agent.sh || true'
                            sh 'cd ${TESTDIR}; ./archive_test_results.sh || true'
                            sh 'cd ${TESTDIR}/..; mv *.zip ${WORKSPACE} || true'
                            sh 'cd ${TESTDIR}; mv *.xml ${WORKSPACE}/${PROJ_PATH}/test || true'
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.10 vagrant destroy -f || true'
                        }
                        failure {
                            script {
                                if  (currentBuild.description == '') {
                                    currentBuild.description = 'K8s 1.10-net-next fail'
                                }
                            }
                        }
                    }
                }
                stage('BDD-Test-PR-K8s-1.14') {
                    environment {
                        GOPATH="${WORKSPACE}/k8s-higher-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.14 ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                    }
                    post {
                        always {
                            sh 'cd ${TESTDIR}; ./post_build_agent.sh || true'
                            sh 'cd ${TESTDIR}; ./archive_test_results.sh || true'
                            sh 'cd ${TESTDIR}/..; mv *.zip ${WORKSPACE} || true'
                            sh 'cd ${TESTDIR}; mv *.xml ${WORKSPACE}/${PROJ_PATH}/test || true'
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.14 vagrant destroy -f || true'
                        }
                        failure {
                            script {
                                if  (currentBuild.description == '') {
                                    currentBuild.description = 'K8s 1.14 fail'
                                }
                            }
                        }
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: '*.zip'
                    junit testDataPublishers: [[$class: 'AttachmentPublisher']], testResults: 'src/github.com/cilium/cilium/test/*.xml'
                    cleanWs()
                }
            }
        }
    }
}
