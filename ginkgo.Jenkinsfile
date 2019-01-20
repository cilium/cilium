@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        TESTDIR = "${WORKSPACE}/${PROJ_PATH}/"
        MEMORY = "4096"
        SERVER_BOX = "cilium/ubuntu"
        NETNEXT=setIfLabel("ci/net-next", "true", "false")
        CNI_INTEGRATION=setIfLabel("integration/cni-flannel", "FLANNEL", "")
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
                BuildIfLabel('area/k8s', 'Cilium-PR-Ginkgo-Tests-K8s')
                BuildIfLabel('area/documentation', 'Cilium-PR-Doc-Tests')
                sh 'env'
                sh 'rm -rf src; mkdir -p src/github.com/cilium'
                sh 'ln -s $WORKSPACE src/github.com/cilium/cilium'
                checkout scm
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
                   sh "cd ${TESTDIR}; make clean-ginkgo-tests || true"
               }
            }
        }
        stage('Boot VMs'){
            options {
                timeout(time: 30, unit: 'MINUTES')
            }
            environment {
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            steps {
                sh 'cd ${TESTDIR}; K8S_VERSION=1.8 vagrant up --no-provision'
                sh 'cd ${TESTDIR}; K8S_VERSION=1.13 vagrant up --no-provision'
            }
        }
        stage('BDD-Test-PR') {
            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
                FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
            }

            options {
                timeout(time: 75, unit: 'MINUTES')
            }

            steps {
                script {
                    parallel(
                        "Runtime":{
                            sh 'cd ${TESTDIR}; vagrant provision runtime' 
                            sh 'cd ${TESTDIR}; ginkgo --focus=" Runtime*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                        },
                        "K8s-1.8":{
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.8 vagrant provision k8s1-1.8; K8S_VERSION=1.8 vagrant provision k8s2-1.8'
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.8 ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                        },
                        "K8s-1.13":{
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.13 vagrant provision k8s1-1.13; K8S_VERSION=1.13 vagrant provision k8s2-1.13'
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.13 ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                        },
                        failFast: "${FAILFAST}".toBoolean()
                    )
                }
            }
            post {
                always {
                    // Temporary workaround to test cleanup
                    // rm -rf ${GOPATH}/src/github.com/cilium/cilium
                    sh 'cd test/; ./post_build_agent.sh || true'
                    sh 'cd test/; ./archive_test_results.sh || true'
                    archiveArtifacts artifacts: '*.zip'
                    junit testDataPublishers: [[$class: 'AttachmentPublisher']], testResults: 'test/*.xml'
                }
            }
        }
    }
    post {
        always {
            sh 'cd ${TESTDIR}/test/; K8S_VERSION=1.8 vagrant destroy -f || true'
            sh 'cd ${TESTDIR}/test/; K8S_VERSION=1.13 vagrant destroy -f || true'
            cleanWs()
        }
    }
}
