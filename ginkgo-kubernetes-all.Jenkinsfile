def failFast = { String branch ->
  if (branch == "origin/master" || branch == "master") {
    return '--failFast=false'
  } else {
    return '--failFast=true'
  }
}

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        MEMORY = "3072"
        TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
        GOPATH="${WORKSPACE}"
    }

    options {
        timeout(time: 140, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
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
            steps {
                sh 'cd ${TESTDIR}; K8S_VERSION=1.8 vagrant up --no-provision'
                sh 'cd ${TESTDIR}; K8S_VERSION=1.9 vagrant up --no-provision'
            }
        }
        stage('BDD-Test-k8s') {
            environment {
                FAILFAST = failFast(env.GIT_BRANCH)
            }
            options {
                timeout(time: 120, unit: 'MINUTES')
            }
            steps {
                parallel(
                    "K8s-1.8":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.8 ginkgo --focus=" K8s*" -v ${FAILFAST}'
                    },
                    "K8s-1.9":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.9 ginkgo --focus=" K8s*" -v ${FAILFAST}'
                    },
                )
            }
            post {
                always {
                    sh 'cd test/; ./archive_test_results.sh || true'
                    archiveArtifacts artifacts: '*.zip'
                    junit testDataPublishers: [[$class: 'AttachmentPublisher']], testResults: 'test/*.xml'
                    sh 'cd test/; ./post_build_agent.sh || true'
                }
            }
        }
        stage('Boot VMs k8s-next'){
            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            steps {
                sh 'cd ${TESTDIR}; K8S_VERSION=1.11 vagrant up --no-provision'
            }
        }
        stage('Non-release-k8s-versions') {
            environment {
                FAILFAST = failFast(env.GIT_BRANCH)
            }
            options {
                timeout(time: 120, unit: 'MINUTES')
            }
            steps {
                parallel(
                    "K8s-1.11":{
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.11 ginkgo --focus=" K8s*" -v ${FAILFAST}'
                    },
                )
            }
            post {
                always {
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
            sh "cd ${TESTDIR}; K8S_VERSION=1.8 vagrant destroy -f || true"
            sh "cd ${TESTDIR}; K8S_VERSION=1.9 vagrant destroy -f || true"
            sh "cd ${TESTDIR}; K8S_VERSION=1.10 vagrant destroy -f || true"
            sh "cd ${TESTDIR}; K8S_VERSION=1.11 vagrant destroy -f || true"
            sh "cd ${TESTDIR}; ./post_build_agent.sh || true"
            cleanWs()
        }
    }
}

