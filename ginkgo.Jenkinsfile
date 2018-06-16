@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        TESTDIR = "${WORKSPACE}/${PROJ_PATH}/"
        MEMORY = "3072"
        SERVER_BOX = "cilium/ubuntu"
    }

    options {
        timeout(time: 180, unit: 'MINUTES')
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
        stage('UnitTesting') {
            options {
                timeout(time: 20, unit: 'MINUTES')
            }

            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/"
            }
            steps {
                sh "cd ${TESTDIR}; make tests-ginkgo"
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
                sh 'cd ${TESTDIR}; K8S_VERSION=1.7 vagrant up --no-provision'
                sh 'cd ${TESTDIR}; K8S_VERSION=1.11 vagrant up --no-provision'
            }
        }
        stage('BDD-Test-PR') {
            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
                FAILFAST=setIfPR("true", "false")
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
            }

            options {
                timeout(time: 90, unit: 'MINUTES')
            }

            steps {
                parallel(
                    "Runtime":{
                        sh 'cd ${TESTDIR}; ginkgo --focus=" RuntimeValidated*" -v --failFast=${FAILFAST}'
                    },
                    "K8s-1.7":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.7 ginkgo --focus=" K8sValidated*" -v --failFast=${FAILFAST}'
                    },
                    "K8s-1.11":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.11 ginkgo --focus=" K8sValidated*" -v --failFast=${FAILFAST}'
                    },
                    failFast: true
                )
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
            sh 'cd ${TESTDIR}/test/; K8S_VERSION=1.7 vagrant destroy -f || true'
            sh 'cd ${TESTDIR}/test/; K8S_VERSION=1.11 vagrant destroy -f || true'
            cleanWs()
        }
    }
}
