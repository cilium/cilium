pipeline {
    agent {
        label 'ginkgo-parallel'
    }
    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        MEMORY = '4096'
        RUN_TEST_SUITE = '1'
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
                    "Print Environment": { sh 'env' },
                    "Runtime":{
                        sh 'cd ${TESTDIR}; ginkgo --focus="Runtime*" -v -noColor'
                    },
                    "K8s-1.7":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.7 ginkgo --focus="K8s*" -v -noColor'
                    },
                    "K8s-1.6":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.6 ginkgo --focus="K8s*" -v -noColor'
                    },
                    "Runtime Tests": {
                         // Make sure that VMs from prior runs are cleaned up in case something went wrong in a prior build.
                         sh 'vagrant destroy -f || true'
                         sh './contrib/vagrant/start.sh'
                     },
                    "K8s multi node Tests": {
                         sh 'cd ./tests/k8s && vagrant destroy -f || true'
                         sh './tests/k8s/start.sh'
                    }
                )
            }
            post {
                always {
                    // Ginkgo test logs
                    junit 'test/*.xml'
                    sh 'cd test/; vagrant destroy -f'
                    sh 'cd test/; K8S_VERSION=1.6 vagrant destroy -f'
                    // Bash test logs
                    sh './tests/copy_files || true'
                    archiveArtifacts artifacts: "cilium-files-runtime-${JOB_BASE_NAME}-${BUILD_NUMBER}.tar.gz", allowEmptyArchive: true
                    sh './tests/k8s/copy_files || true'
                    archiveArtifacts artifacts: "cilium-files-k8s-${JOB_BASE_NAME}-${BUILD_NUMBER}.tar.gz", allowEmptyArchive: true
                    sh 'rm -rf ${WORKSPACE}/cilium-files*${JOB_BASE_NAME}-${BUILD_NUMBER}* ${WORKSPACE}/tests/cilium-files ${WORKSPACE}/tests/k8s/tests/cilium-files'
                    sh 'ls'
                    sh 'vagrant destroy -f'
                    sh 'cd ./tests/k8s && vagrant destroy -f'
                }
            }
        }
    }
}
