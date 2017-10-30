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
        }
        stage('BDD-Test') {
            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            steps {
                parallel(
                    "Runtime":{
                        sh 'cd ${TESTDIR}; ginkgo --focus="Runtime*" -v -noColor'
                    },
                    "K8s-1.7":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.7 ginkgo --focus="K8s*" -v -noColor'
                    },
                    "K8s-1.6":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.6 ginkgo --focus="K8s*" -v -noColor'
                    },
                )
            }
            post {
                always {
                    junit 'test/*.xml'
                    // Temporary workaround to test cleanup
                    // rm -rf ${GOPATH}/src/github.com/cilium/cilium
                    sh 'cd test/; vagrant destroy -f'
                    sh 'cd test/; K8S_VERSION=1.6 vagrant destroy -f'
                }
            }
        }
    }
}
