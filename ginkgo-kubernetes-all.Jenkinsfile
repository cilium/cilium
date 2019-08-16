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
        CNI_INTEGRATION=setIfLabel("integration/cni-flannel", "FLANNEL", "")
        GINKGO_TIMEOUT="98m"
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
        stage('Copy code and boot VMs 1.{12,13}'){

            options {
                timeout(time: 60, unit: 'MINUTES')
            }

            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }

            parallel {
                stage('Boot vms 1.12') {
                    environment {
                        TESTED_SUITE="1.12"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        retry(3) {
                            sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant destroy k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --force'
                            sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant up k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --provision'
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.12 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('Boot vms 1.13') {
                    environment {
                        TESTED_SUITE="1.13"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        retry(3) {
                            sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant destroy k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --force'
                            sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant up k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --provision'
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.13 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
            }
        }
        stage('BDD-Test-k8s-1.12-and-1.13') {
            environment {
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
            }
            options {
                timeout(time: 100, unit: 'MINUTES')
            }
            parallel {
                stage('BDD-Test-k8s-1.12') {
                    environment {
                        TESTED_SUITE="1.12"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT}'
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
                                    currentBuild.displayName = 'K8s 1.12 tests fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('BDD-Test-k8s-1.13') {
                    environment {
                        TESTED_SUITE="1.13"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT}'
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
                                    currentBuild.displayName = 'K8s 1.13 tests fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
            }
        }

        stage('Copy code and boot VMs 1.{14}'){

            options {
                timeout(time: 60, unit: 'MINUTES')
            }

            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }

            parallel {
                stage('Boot vms 1.14') {
                    environment {
                        TESTED_SUITE="1.14"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        retry(3) {
                            sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant destroy k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --force'
                            sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant up k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --provision'
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.14 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                /* stage('Boot vms 1.16') {
                    environment {
                        TESTED_SUITE="1.16"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        retry(3) {
                            sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant destroy k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --force'
                            sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} vagrant up k8s1-${TESTED_SUITE} k8s2-${TESTED_SUITE} --provision'
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.16 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }*/
            }
        }
        stage('BDD-Test-k8s-1.14') {
            environment {
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
            }
            options {
                timeout(time: 100, unit: 'MINUTES')
            }
            parallel {
                stage('BDD-Test-k8s-1.14') {
                    environment {
                        TESTED_SUITE="1.14"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT}'
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
                                    currentBuild.displayName = 'K8s 1.14 tests fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                /*stage('BDD-Test-k8s-1.16') {
                    environment {
                        TESTED_SUITE="1.16"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; K8S_VERSION=${TESTED_SUITE} ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT}'
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
                                    currentBuild.displayName = 'K8s 1.16 tests fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }*/
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: '*.zip'
            junit testDataPublishers: [[$class: 'AttachmentPublisher']], testResults: 'src/github.com/cilium/cilium/test/*.xml'
            cleanWs()
            sh '/usr/local/bin/cleanup || true'
        }
        success {
            Status("SUCCESS", "${env.JOB_NAME}")
        }
        failure {
            Status("FAILURE", "${env.JOB_NAME}")
        }
    }
}
