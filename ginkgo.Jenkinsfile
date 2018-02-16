pipeline {
    agent {
        label 'ginkgo'
    }
    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
    }

    options {
        timeout(time: 120, unit: 'MINUTES')
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
        stage('UnitTesting') {
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
            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            steps {
                sh 'cd ${TESTDIR}; K8S_VERSION=1.8 vagrant up --no-provision'
                sh 'cd ${TESTDIR}; K8S_VERSION=1.6 vagrant up --no-provision'
            }
            post {
                failure {
                    sh "cd ${TESTDIR}; K8S_VERSION=1.8 vagrant destroy -f || true"
                    sh "cd ${TESTDIR}; K8S_VERSION=1.6 vagrant destroy -f || true"
                }
            }
        }
        stage('BDD-Test-Master') {
            when {
                expression {
                    return env.GIT_BRANCH == 'origin/master';
                }
            }
            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            options {
                timeout(time: 90, unit: 'MINUTES')
            }
            steps {
                parallel(
                    "Runtime":{
                        sh 'cd ${TESTDIR}; ginkgo --focus="Runtime*" -noColor'
                    },
                    "K8s-1.8":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.8 ginkgo --focus=" K8s*" -noColor'
                    },
                    "K8s-1.6":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.6 ginkgo --focus=" K8s*" -noColor'
                    },
                    failFast: true
                )
            }
            post {
                always {
                    junit 'test/*.xml'
                    // Temporary workaround to test cleanup
                    // rm -rf ${GOPATH}/src/github.com/cilium/cilium
                    sh 'cd test/; ./post_build_agent.sh || true'
                    sh 'cd test/; K8S_VERSION=1.8 vagrant destroy -f || true'
                    sh 'cd test/; K8S_VERSION=1.6 vagrant destroy -f || true'
                    sh 'cd test/; ./archive_test_results.sh || true'
                    archiveArtifacts artifacts: "test_results_${JOB_BASE_NAME}_${BUILD_NUMBER}.tar", allowEmptyArchive: true
                }
            }
        }
        stage('BDD-Test-PR') {
            when {
                expression {
                    return env.GIT_BRANCH != 'origin/master';
                }
            }
            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            options {
                timeout(time: 90, unit: 'MINUTES')
            }
            steps {
                parallel(
                    "Runtime":{
                        sh 'cd ${TESTDIR}; ginkgo --focus="RuntimeValidated*" -v -noColor'
                    },
                    "K8s-1.8":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.8 ginkgo --focus=" K8sValidated*" -v -noColor'
                    },
                    "K8s-1.6":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.6 ginkgo --focus=" K8sValidated*" -v -noColor'
                    },
                    failFast: true
                )
            }
            post {
                always {
                    junit 'test/*.xml'
                    // Temporary workaround to test cleanup
                    // rm -rf ${GOPATH}/src/github.com/cilium/cilium
                    sh 'cd test/; ./post_build_agent.sh || true'
                    sh 'cd test/; K8S_VERSION=1.8 vagrant destroy -f || true'
                    sh 'cd test/; K8S_VERSION=1.6 vagrant destroy -f || true'
                    sh 'cd test/; ./archive_test_results.sh || true'
                    archiveArtifacts artifacts: "test_results_${JOB_BASE_NAME}_${BUILD_NUMBER}.tar", allowEmptyArchive: true
                }
            }
        }
    }
    post {
        always {
            cleanWs()
        }
    }
}
