@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        VM_MEMORY = "8192"
        VM_CPUS = "4"
        GINKGO_TIMEOUT="150m"
        DEFAULT_KERNEL="""${sh(
            returnStdout: true,
            script: 'echo -n "${JobKernelVersion}"'
            )}"""
        NETNEXT="""${sh(
            returnStdout: true,
            script: 'if [ "${JobKernelVersion}" = "net-next" ]; then echo -n "1"; else echo -n "0"; fi'
            )}"""
        TESTED_SUITE="runtime"
        FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
        RUN_QUARANTINED="""${sh(
				returnStdout: true,
				script: 'if [ "${RunQuarantined}" = "" ]; then echo -n "false"; else echo -n "${RunQuarantined}"; fi'
            )}"""
        RACE="""${sh(
                returnStdout: true,
                script: 'if [ "${run_with_race_detection}" = "" ]; then echo -n ""; else echo -n "1"; fi'
            )}"""
        LOCKDEBUG="""${sh(
                returnStdout: true,
                script: 'if [ "${run_with_race_detection}" = "" ]; then echo -n ""; else echo -n "1"; fi'
            )}"""
        BASE_IMAGE="""${sh(
                returnStdout: true,
                script: 'if [ "${run_with_race_detection}" = "" ]; then echo -n "scratch"; else echo -n "quay.io/cilium/cilium-runtime:1230e4791f50827ffed6354270f36f7ba304cc98@sha256:12e8fc4bacc93711f71130527e2a12d41d88a212bb4e8e4ff4c3ced7aea1cc5c"; fi'
            )}"""
    }

    options {
        timeout(time: 300, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Set build name') {
            when {
                not {
                    anyOf {
                        environment name: 'ghprbPullTitle', value: null
                        environment name: 'ghprbPullLink', value: null
                    }
                }
            }
            steps {
                   script {
                       currentBuild.displayName = env.getProperty('ghprbPullTitle') + '  ' + env.getProperty('ghprbPullLink') + '  ' + currentBuild.displayName
                   }
            }
        }
        stage('Checkout') {
            options {
                timeout(time: 30, unit: 'MINUTES')
            }

            steps {
                sh 'env'
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
        stage('Log in to dockerhub') {
            steps{
                withCredentials([usernamePassword(credentialsId: 'CILIUM_BOT_DUMMY', usernameVariable: 'DOCKER_LOGIN', passwordVariable: 'DOCKER_PASSWORD')]) {
                    sh 'echo ${DOCKER_PASSWORD} | docker login -u ${DOCKER_LOGIN} --password-stdin'
                }
            }
        }
        stage ("Copy code and boot vms"){
            options {
                timeout(time: 50, unit: 'MINUTES')
            }

            environment {
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
                GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                KUBECONFIG="vagrant-kubeconfig"
            }
            steps {
                sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                withCredentials([usernamePassword(credentialsId: 'CILIUM_BOT_DUMMY', usernameVariable: 'DOCKER_LOGIN', passwordVariable: 'DOCKER_PASSWORD')]) {
                    retry(3) {
                        dir("${TESTDIR}") {
                            sh 'vagrant destroy runtime --force'
                            sh 'KERNEL=$(python3 get-gh-comment-info.py "${ghprbCommentBody}" --retrieve=kernel_version | sed "s/^$/${DEFAULT_KERNEL}/") vagrant up runtime --provision'
                        }
                    }
                }
            }
            post {
                unsuccessful {
                    script {
                        if  (!currentBuild.displayName.contains('fail')) {
                            currentBuild.displayName = 'runtime vm provisioning fail\n' + currentBuild.displayName
                        }
                    }
                }
            }
        }
        stage ("BDD-Test-PR"){
            options {
                timeout(time: 180, unit: 'MINUTES')
            }
            environment {
                GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                TESTDIR="${GOPATH}/${PROJ_PATH}/test"
            }
            steps {
                sh 'cd ${TESTDIR}; ginkgo -seed=3898027111 -focus="$(python3 get-gh-comment-info.py "${ghprbCommentBody}" | sed "s/^$/Runtime/" | sed "s/K8s.*/NoTests/")" --tags=integration_tests -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.runQuarantined=${RUN_QUARANTINED}'
            }
            post {
                always {
                    sh 'cd ${TESTDIR}; ./post_build_agent.sh || true'
                    sh 'cd ${TESTDIR}; ./archive_test_results_eks.sh || true'
                    sh 'cd ${TESTDIR}/..; mv *.zip ${WORKSPACE} || true'
                    sh 'cd ${TESTDIR}; mv *.xml ${WORKSPACE}/${PROJ_PATH}/test || true'
                    sh 'cd ${TESTDIR}; vagrant destroy -f || true'
                    archiveArtifacts artifacts: '*.zip'
                    junit testDataPublishers: [[$class: 'AttachmentPublisher']], testResults: 'src/github.com/cilium/cilium/test/*.xml'
                }
                unsuccessful {
                    script {
                        if  (!currentBuild.displayName.contains('fail')) {
                            currentBuild.displayName = 'Runtime tests fail\n' + currentBuild.displayName
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            sh 'lscpu'
            cleanWs()
            sh '/usr/local/bin/cleanup || true'
        }
    }
}
