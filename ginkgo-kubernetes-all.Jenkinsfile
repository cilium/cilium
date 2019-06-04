@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    parameters {
        string(defaultValue: '${ghprbPullDescription}', name: 'ghprbPullDescription')
        string(defaultValue: '${ghprbActualCommit}', name: 'ghprbActualCommit')
        string(defaultValue: '${ghprbTriggerAuthorLoginMention}', name: 'ghprbTriggerAuthorLoginMention')
        string(defaultValue: '${ghprbPullAuthorLoginMention}', name: 'ghprbPullAuthorLoginMention')
        string(defaultValue: '${ghprbGhRepository}', name: 'ghprbGhRepository')
        string(defaultValue: '${ghprbPullLongDescription}', name: 'ghprbPullLongDescription')
        string(defaultValue: '${ghprbCredentialsId}', name: 'ghprbCredentialsId')
        string(defaultValue: '${ghprbTriggerAuthorLogin}', name: 'ghprbTriggerAuthorLogin')
        string(defaultValue: '${ghprbPullAuthorLogin}', name: 'ghprbPullAuthorLogin')
        string(defaultValue: '${ghprbTriggerAuthor}', name: 'ghprbTriggerAuthor')
        string(defaultValue: '${ghprbCommentBody}', name: 'ghprbCommentBody')
        string(defaultValue: '${ghprbPullTitle}', name: 'ghprbPullTitle')
        string(defaultValue: '${ghprbPullLink}', name: 'ghprbPullLink')
        string(defaultValue: '${ghprbAuthorRepoGitUrl}', name: 'ghprbAuthorRepoGitUrl')
        string(defaultValue: '${ghprbTargetBranch}', name: 'ghprbTargetBranch')
        string(defaultValue: '${ghprbPullId}', name: 'ghprbPullId')
        string(defaultValue: '${ghprbActualCommitAuthor}', name: 'ghprbActualCommitAuthor')
        string(defaultValue: '${ghprbActualCommitAuthorEmail}', name: 'ghprbActualCommitAuthorEmail')
        string(defaultValue: '${ghprbTriggerAuthorEmail}', name: 'ghprbTriggerAuthorEmail')
        string(defaultValue: '${GIT_BRANCH}', name: 'GIT_BRANCH')
        string(defaultValue: '${ghprbPullAuthorEmail}', name: 'ghprbPullAuthorEmail')
        string(defaultValue: '${sha1}', name: 'sha1')
        string(defaultValue: '${ghprbSourceBranch}', name: 'ghprbSourceBranch')
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        MEMORY = "4096"
        TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
        GOPATH="${WORKSPACE}"
        SERVER_BOX = "cilium/ubuntu"
        FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
    }

    options {
        timeout(time: 300, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Checkout') {
            options {
                timeout(time: 20, unit: 'MINUTES')
            }

            steps {
                sh 'env'
                Status("PENDING", "${env.JOB_NAME}")
                checkout scm
                sh 'mkdir -p ${PROJ_PATH}'
                sh 'ls -A | grep -v src | xargs mv -t ${PROJ_PATH}'
                sh '/usr/local/bin/cleanup || true'
            }
        }
        stage('Preload vagrant boxes') {
            steps {
                sh '/usr/local/bin/add_vagrant_box ${WORKSPACE}/${PROJ_PATH}/vagrant_box_defaults.rb'
            }
            post {
                unsuccessful {
                    script {
                        if  (!currentBuild.displayName.contains('fail')) {
                            currentBuild.displayName = 'preload vagrant boxes fail' + currentBuild.displayName
                        }
                    }
                }
            }
        }
        stage('Copy code and boot VMs 1.{8,9}'){

            options {
                timeout(time: 30, unit: 'MINUTES')
            }

            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }

            parallel {
                stage('Boot vms 1.8') {
                    environment {
                        TESTED_SUITE="1.8"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant up k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --provision'
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.8 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('Boot vms 1.9') {
                    environment {
                        TESTED_SUITE="1.9"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant up k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --provision'
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.9 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
            }
        }
        stage('BDD-Test-k8s-1.8-and-1.9') {
            environment {
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
            }
            options {
                timeout(time: 100, unit: 'MINUTES')
            }
            failFast true
            parallel {
                stage('BDD-Test-k8s-1.8') {
                    environment {
                        TESTED_SUITE="1.8"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                    }
                    post {
                        always {
                            sh 'cd ${TESTDIR}; ./post_build_agent.sh || true'
                            sh 'cd ${TESTDIR}; ./archive_test_results.sh || true'
                            sh 'cd ${TESTDIR}/..; mv *.zip ${WORKSPACE} || true'
                            sh 'cd ${TESTDIR}; mv *.xml ${WORKSPACE}/${PROJ_PATH}/test || true'
                            sh 'cd ${TESTDIR}; vagrant destroy -f || true'
                        }
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8s 1.8 tests fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('BDD-Test-k8s-1.9') {
                    environment {
                        TESTED_SUITE="1.9"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                    }
                    post {
                        always {
                            sh 'cd ${TESTDIR}; ./post_build_agent.sh || true'
                            sh 'cd ${TESTDIR}; ./archive_test_results.sh || true'
                            sh 'cd ${TESTDIR}/..; mv *.zip ${WORKSPACE} || true'
                            sh 'cd ${TESTDIR}; mv *.xml ${WORKSPACE}/${PROJ_PATH}/test || true'
                            sh 'cd ${TESTDIR}; vagrant destroy -f || true'
                        }
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8s 1.9 tests fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
            }
        }

        stage('Copy code and boot VMs 1.{10,11}'){

            options {
                timeout(time: 30, unit: 'MINUTES')
            }

            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }

            parallel {
                stage('Boot vms 1.10') {
                    environment {
                        TESTED_SUITE="1.10"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant up k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --provision'
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.10 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('Boot vms 1.11') {
                    environment {
                        TESTED_SUITE="1.11"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant up k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --provision'
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.11 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
            }
        }
        stage('BDD-Test-k8s-1.10-and-1.11') {
            environment {
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
            }
            options {
                timeout(time: 100, unit: 'MINUTES')
            }
            failFast true
            parallel {
                stage('BDD-Test-k8s-1.10') {
                    environment {
                        TESTED_SUITE="1.10"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                    }
                    post {
                        always {
                            sh 'cd ${TESTDIR}; ./post_build_agent.sh || true'
                            sh 'cd ${TESTDIR}; ./archive_test_results.sh || true'
                            sh 'cd ${TESTDIR}/..; mv *.zip ${WORKSPACE} || true'
                            sh 'cd ${TESTDIR}; mv *.xml ${WORKSPACE}/${PROJ_PATH}/test || true'
                            sh 'cd ${TESTDIR}; vagrant destroy -f || true'
                        }
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8s 1.10 tests fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('BDD-Test-k8s-1.11') {
                    environment {
                        TESTED_SUITE="1.11"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                    }
                    post {
                        always {
                            sh 'cd ${TESTDIR}; ./post_build_agent.sh || true'
                            sh 'cd ${TESTDIR}; ./archive_test_results.sh || true'
                            sh 'cd ${TESTDIR}/..; mv *.zip ${WORKSPACE} || true'
                            sh 'cd ${TESTDIR}; mv *.xml ${WORKSPACE}/${PROJ_PATH}/test || true'
                            sh 'cd ${TESTDIR}; vagrant destroy -f || true'
                        }
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8s 1.11 tests fail\n' + currentBuild.displayName
                                }
                            }
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
        success {
            Status("SUCCESS", "${env.JOB_NAME}")
        }
        failure {
            Status("FAILURE", "${env.JOB_NAME}")
        }
    }
}
