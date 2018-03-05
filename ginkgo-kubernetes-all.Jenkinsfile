pipeline {
    agent {
        label 'baremetal'
    }
    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
    }

    options {
        timeout(time: 90, unit: 'MINUTES')
        timestamps()
    }
    stages {
        stage('Checkout') {
            steps {
                sh 'env'
                sh 'rm -rf src; mkdir -p src/github.com/cilium'
                sh 'ln -s $WORKSPACE src/github.com/cilium/cilium'
                checkout scm
            }
        }
        stage('Boot VMs'){
            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            steps {
                sh 'cd ${TESTDIR}; K8S_VERSION=1.7 vagrant up --no-provision'
                sh 'cd ${TESTDIR}; K8S_VERSION=1.8 vagrant up --no-provision'
            }
        }
        stage('BDD-Test-k8s') {
            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            options {
                timeout(time: 60, unit: 'MINUTES')
            }
            steps {
                parallel(
                    "K8s-1.7":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.7 ginkgo --focus=" K8s*" -v -noColor'
                    },
                    "K8s-1.8":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.8 ginkgo --focus=" K8s*" -v -noColor'
                    },
                )
            }
            post {
                always {
                    junit 'test/*.xml'
                    sh 'cd test/; ./post_build_agent.sh || true'
                    sh 'cd test/; ./archive_test_results.sh || true'
                    archiveArtifacts artifacts: "test_results_${JOB_BASE_NAME}_${BUILD_NUMBER}.tar", allowEmptyArchive: true
                }
            }
        }
        stage('Non-release-k8s-versions') {
            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            options {
                timeout(time: 60, unit: 'MINUTES')
            }
            steps {
                parallel(
                    "K8s-1.10":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.10 ginkgo --focus=" K8s*" -v -noColor'
                    },
                    "K8s-1.11":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.11 ginkgo --focus=" K8s*" -v -noColor'
                    },
                )
            }
            post {
                always {
                    junit 'test/*.xml'
                    sh 'cd test/; ./post_build_agent.sh || true'
                    sh 'cd test/; ./archive_test_results.sh || true'
                    archiveArtifacts artifacts: "test_results_${JOB_BASE_NAME}_${BUILD_NUMBER}.tar", allowEmptyArchive: true
                }
            }
        }
    }
    post {
        always {
            cleanWs()
            sh "cd ${TESTDIR}; K8S_VERSION=1.7 vagrant destroy -f || true"
            sh "cd ${TESTDIR}; K8S_VERSION=1.8 vagrant destroy -f || true"
            sh "cd ${TESTDIR}; K8S_VERSION=1.10 vagrant destroy -f || true"
            sh "cd ${TESTDIR}; K8S_VERSION=1.11 vagrant destroy -f || true"
        }
    }
}
