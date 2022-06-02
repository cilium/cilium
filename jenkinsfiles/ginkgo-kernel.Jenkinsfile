@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        VM_MEMORY = "8192"
        VM_CPUS = "3"
        GOPATH="${WORKSPACE}"
        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
        GINKGO_TIMEOUT="170m"
        RUN_QUARANTINED="""${sh(
                returnStdout: true,
                script: 'if [ "${RunQuarantined}" = "" ]; then echo -n "false"; else echo -n "${RunQuarantined}"; fi'
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
                checkout scm
                sh 'mkdir -p ${PROJ_PATH}'
                sh 'ls -A | grep -v src | xargs mv -t ${PROJ_PATH}'
                sh '/usr/local/bin/cleanup || true'
            }
        }
        stage('Set programmatic env vars') {
            steps {
                // retrieve k8s and kernel versions from gh comment, then from job parameter, default to 1.24 for k8s, 419 for kernel
                script {
                    flags = env.ghprbCommentBody?.replace("\\", "")
                    env.K8S_VERSION = sh script: '''
                        if [ "${ghprbCommentBody}" != "" ]; then
                            python3 ${TESTDIR}/get-gh-comment-info.py ''' + flags + ''' --retrieve="k8s_version" | \
                            sed "s/^$/${JobK8sVersion:-1.24}/" | \
                            sed 's/^"//' | sed 's/"$//' | \
                            xargs echo -n
                        else
                            echo -n ${JobK8sVersion:-1.24}
                        fi''', returnStdout: true
                    env.KERNEL = sh script: '''
                        if [ "${ghprbCommentBody}" != "" ]; then
                            python3 ${TESTDIR}/get-gh-comment-info.py ''' + flags + ''' --retrieve="kernel_version" | \
                            sed "s/^$/${JobKernelVersion:-419}/" | \
                            sed 's/^"//' | sed 's/"$//' | \
                            xargs echo -n
                        else
                             echo -n ${JobKernelVersion:-419}
                        fi''', returnStdout: true
                    env.FOCUS = sh script: '''
                        if [ "${ghprbCommentBody}" != "" ]; then
                            python3 ${TESTDIR}/get-gh-comment-info.py ''' + flags + ''' --retrieve="focus" | \
                            sed "s/^$/K8s/" | \
                            sed "s/Runtime.*/NoTests/" | \
                            sed 's/^"//' | sed 's/"$//' | \
                            xargs echo -n
                        else
                            echo -n "K8s"
                        fi''', returnStdout: true

                    env.IMAGE_REGISTRY = sh script: 'echo -n ${JobImageRegistry:-quay.io/cilium}', returnStdout: true

                    if (env.ghprbActualCommit?.trim()) {
                        env.DOCKER_TAG = env.ghprbActualCommit
                    } else {
                        env.DOCKER_TAG = env.GIT_COMMIT
                    }
                    if (env.run_with_race_detection?.trim()) {
                        env.DOCKER_TAG = env.DOCKER_TAG + "-race"
                        env.RACE = 1
                        env.LOCKDEBUG = 1
                        env.BASE_IMAGE = "quay.io/cilium/cilium-runtime:ad71fe7980638d9b7d4c57fc07604cea9a0a1371@sha256:70972d83f30c8204564451ad57e338a45cf9ca140c5a00310c91c9b29a1d851e"
                    }
                }
            }
        }
        stage('Print env vars') {
            steps {
                sh 'env'
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
        stage("Wait for Cilium images and boot vms"){
            parallel {
                stage ("Copy code and boot vms"){
                    options {
                        timeout(time: 30, unit: 'MINUTES')
                    }

                    environment {
                        FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                        CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
                        KUBECONFIG="vagrant-kubeconfig"

                        // We need to define all ${KERNEL}-dependent env vars in stage instead of top environment block
                        // because jenkins doesn't initialize these values sequentially within one block

                        // We set KUBEPROXY="0" if we are running net-next; otherwise, KUBEPROXY=""
                        // If we are running in net-next, we need to set NETNEXT=1, K8S_NODES=3, and NO_CILIUM_ON_NODE="k8s3";
                        // otherwise we set NETNEXT=0, K8S_NODES=2, and NO_CILIUM_ON_NODE="".
                        NETNEXT="""${sh(
                            returnStdout: true,
                            script: 'if [ "${KERNEL}" = "net-next" ]; then echo -n "1"; else echo -n "0"; fi'
                            )}"""
                        K8S_NODES="""${sh(
                            returnStdout: true,
                            script: 'if [ "${KERNEL}" = "net-next" ]; then echo -n "3"; else echo -n "2"; fi'
                            )}"""
                        NO_CILIUM_ON_NODE="""${sh(
                            returnStdout: true,
                            script: 'if [ "${KERNEL}" = "net-next" ]; then echo -n "k8s3"; else echo -n ""; fi'
                            )}"""
                        KUBEPROXY="""${sh(
                            returnStdout: true,
                            script: 'if [ "${KERNEL}" = "net-next" ]; then echo -n "0"; else echo -n ""; fi'
                            )}"""
                    }
                    steps {
                        withCredentials([usernamePassword(credentialsId: 'CILIUM_BOT_DUMMY', usernameVariable: 'DOCKER_LOGIN', passwordVariable: 'DOCKER_PASSWORD')]) {
                            dir("${TESTDIR}") {
                                sh 'CILIUM_REGISTRY="$(./print-node-ip.sh)" timeout 25m ./vagrant-ci-start.sh'
                            }
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8s vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage ("Wait for images") {
                    options {
                        timeout(time: 20, unit: 'MINUTES')
                    }
                    steps {
                        retry(25) {
                            sleep(time: 60)
                            sh 'docker manifest inspect ${IMAGE_REGISTRY}/cilium-ci:${DOCKER_TAG} &> /dev/null'
                            sh 'docker manifest inspect ${IMAGE_REGISTRY}/operator-generic-ci:${DOCKER_TAG} &> /dev/null'
                            sh 'docker manifest inspect ${IMAGE_REGISTRY}/hubble-relay-ci:${DOCKER_TAG} &> /dev/null'
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'Wait for quay images timed out\n' + currentBuild.displayName
                                }
                            }
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
                KUBECONFIG="${TESTDIR}/vagrant-kubeconfig"
                FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
                HOST_FIREWALL=setIfLabel("ci/host-firewall", "1", "0")

                // We need to define all ${KERNEL}-dependent env vars in stage instead of top environment block
                // because jenkins doesn't initialize these values sequentially within one block

                // We set KUBEPROXY="0" if we are running net-next; otherwise, KUBEPROXY=""
                // If we are running in net-next, we need to set NETNEXT=1, K8S_NODES=3, and NO_CILIUM_ON_NODE="k8s3";
                // otherwise we set NETNEXT=0, K8S_NODES=2, and NO_CILIUM_ON_NODE="".
                NETNEXT="""${sh(
                    returnStdout: true,
                    script: 'if [ "${KERNEL}" = "net-next" ]; then echo -n "1"; else echo -n "0"; fi'
                    )}"""
                K8S_NODES="""${sh(
                    returnStdout: true,
                    script: 'if [ "${KERNEL}" = "net-next" ]; then echo -n "3"; else echo -n "2"; fi'
                    )}"""
                NO_CILIUM_ON_NODE="""${sh(
                    returnStdout: true,
                    script: 'if [ "${KERNEL}" = "net-next" ]; then echo -n "k8s3"; else echo -n ""; fi'
                    )}"""
                KUBEPROXY="""${sh(
                    returnStdout: true,
                    script: 'if [ "${KERNEL}" = "net-next" ]; then echo -n "0"; else echo -n ""; fi'
                    )}"""
                CILIUM_IMAGE = "${IMAGE_REGISTRY}/cilium-ci"
                CILIUM_TAG = "${DOCKER_TAG}"
                CILIUM_OPERATOR_IMAGE= "${IMAGE_REGISTRY}/operator"
                CILIUM_OPERATOR_TAG = "${DOCKER_TAG}"
                HUBBLE_RELAY_IMAGE= "${IMAGE_REGISTRY}/hubble-relay-ci"
                HUBBLE_RELAY_TAG = "${DOCKER_TAG}"
            }
            steps {
                sh 'env'
                sh 'cd ${TESTDIR}; HOME=${GOPATH} ginkgo --focus="${FOCUS}" --tags=integration_tests -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.kubeconfig=${TESTDIR}/vagrant-kubeconfig -cilium.passCLIEnvironment=true -cilium.runQuarantined=${RUN_QUARANTINED} -cilium.image=${CILIUM_IMAGE} -cilium.tag=${CILIUM_TAG} -cilium.operator-image=${CILIUM_OPERATOR_IMAGE} -cilium.operator-tag=${CILIUM_OPERATOR_TAG} -cilium.hubble-relay-image=${HUBBLE_RELAY_IMAGE} -cilium.hubble-relay-tag=${HUBBLE_RELAY_TAG} -cilium.operator-suffix="-ci"'
            }
            post {
                always {
                    sh 'cd ${TESTDIR}; ./post_build_agent.sh || true'
                    sh 'cd ${TESTDIR}; ./archive_test_results.sh || true'
                    sh 'cd ${TESTDIR}/..; mv *.zip ${WORKSPACE} || true'
                    sh 'cd ${TESTDIR}; mv *.xml ${WORKSPACE}/${PROJ_PATH}/test || true'
                    sh 'cd ${TESTDIR}; vagrant destroy -f || true'
                    archiveArtifacts artifacts: '*.zip'
                    junit testDataPublishers: [[$class: 'AttachmentPublisher']], testResults: 'src/github.com/cilium/cilium/test/*.xml'
                }
                unsuccessful {
                    script {
                        if  (!currentBuild.displayName.contains('fail')) {
                            currentBuild.displayName = 'K8s tests fail\n' + currentBuild.displayName
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
