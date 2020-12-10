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
                script: 'if [ "${run_with_race_detection}" = "" ]; then echo -n "scratch"; else echo -n "quay.io/cilium/cilium-runtime:2020-12-10@sha256:ee6f0f81fa73125234466c13fd16bed30cc3209daa2f57098f63e0285779e5f3"; fi'
            )}"""
    }

    options {
        timeout(time: 300, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Print env vars') {
            steps {
                sh 'env'

            }
        }
        stage('Set build name') {
            when {
                not {environment name: 'GIT_BRANCH', value: 'origin/master'}
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
                // retrieve k8s and kernel versions from gh comment, then from job parameter, default to 1.19 for k8s, 419 for kernel
                script {
                    flags = env.ghprbCommentBody?.replace("\\", "")
                    env.K8S_VERSION = sh script: '''
                        if [ "${ghprbCommentBody}" != "" ]; then
                            python ${TESTDIR}/get-gh-comment-info.py ''' + flags + ''' --retrieve="k8s_version" | \
                            sed "s/^$/${JobK8sVersion:-1.19}/" | \
                            sed 's/^"//' | sed 's/"$//' | \
                            xargs echo -n
                        else
                            echo -n ${JobK8sVersion:-1.19}
                        fi''', returnStdout: true
                    env.KERNEL = sh script: '''
                        if [ "${ghprbCommentBody}" != "" ]; then
                            python ${TESTDIR}/get-gh-comment-info.py ''' + flags + ''' --retrieve="kernel_version" | \
                            sed "s/^$/${JobKernelVersion:-419}/" | \
                            sed 's/^"//' | sed 's/"$//' | \
                            xargs echo -n
                        else
                             echo -n ${JobKernelVersion:-419}
                        fi''', returnStdout: true
                    env.FOCUS = sh script: '''
                        if [ "${ghprbCommentBody}" != "" ]; then
                            python ${TESTDIR}/get-gh-comment-info.py ''' + flags + ''' --retrieve="focus" | \
                            sed "s/^$/K8s/" | \
                            sed "s/Runtime.*/NoTests/" | \
                            sed 's/^"//' | sed 's/"$//' | \
                            xargs echo -n
                        else
                            echo -n "K8s"
                        fi''', returnStdout: true
                }
            }
        }
        stage('Precheck') {
            options {
                timeout(time: 30, unit: 'MINUTES')
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
               unsuccessful {
                   script {
                       if  (!currentBuild.displayName.contains('fail')) {
                           currentBuild.displayName = 'precheck fail\n' + currentBuild.displayName
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
        stage('Make Cilium images') {
            environment {
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            steps {
                retry(3){
                    sh 'cd ${TESTDIR}; ./make-images-push-to-local-registry.sh $(./print-node-ip.sh) latest'
                }
            }
            post {
                unsuccessful {
                    script {
                        if  (!currentBuild.displayName.contains('fail')) {
                            currentBuild.displayName = 'building or pushing Cilium images failed ' + currentBuild.displayName
                        }
                    }
                }
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
        stage ("Copy code and boot vms"){
            options {
                timeout(time: 50, unit: 'MINUTES')
            }

            environment {
                FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
                KUBECONFIG="vagrant-kubeconfig"

                // We need to define all ${KERNEL}-dependent env vars in stage instead of top environment block
                // because jenkins doesn't initialize these values sequentially within one block

                // We set KUBEPROXY="0" if we are running net-next or 4.19; otherwise, KUBEPROXY=""
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
                    script: 'if [ "${KERNEL}" = "net-next" ] || [ "${KERNEL}" = "419" ]; then echo -n "0"; else echo -n ""; fi'
                    )}"""
            }
            steps {
                withCredentials([usernamePassword(credentialsId: 'CILIUM_BOT_DUMMY', usernameVariable: 'DOCKER_LOGIN', passwordVariable: 'DOCKER_PASSWORD')]) {
                    retry(3) {
                        dir("${TESTDIR}") {
                            sh 'CILIUM_REGISTRY="$(./print-node-ip.sh)" timeout 15m ./vagrant-ci-start.sh'
                        }
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

                // We set KUBEPROXY="0" if we are running net-next or 4.19; otherwise, KUBEPROXY=""
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
                    script: 'if [ "${KERNEL}" = "net-next" ] || [ "${KERNEL}" = "419" ]; then echo -n "0"; else echo -n ""; fi'
                    )}"""
                CILIUM_IMAGE = """${sh(
                        returnStdout: true,
                        script: 'echo -n $(${TESTDIR}/print-node-ip.sh)/cilium/cilium'
                        )}"""
                CILIUM_TAG = "latest"
                CILIUM_OPERATOR_IMAGE= """${sh(
                        returnStdout: true,
                        script: 'echo -n $(${TESTDIR}/print-node-ip.sh)/cilium/operator'
                        )}"""
                CILIUM_OPERATOR_TAG = "latest"
                HUBBLE_RELAY_IMAGE= """${sh(
                        returnStdout: true,
                        script: 'echo -n $(${TESTDIR}/print-node-ip.sh)/cilium/hubble-relay'
                        )}"""
                HUBBLE_RELAY_TAG = "latest"
            }
            steps {
                sh 'env'
                sh 'cd ${TESTDIR}; HOME=${GOPATH} ginkgo --focus="${FOCUS}" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.kubeconfig=${TESTDIR}/vagrant-kubeconfig -cilium.passCLIEnvironment=true -cilium.runQuarantined=${RUN_QUARANTINED} -cilium.image=${CILIUM_IMAGE} -cilium.tag=${CILIUM_TAG} -cilium.operator-image=${CILIUM_OPERATOR_IMAGE} -cilium.operator-tag=${CILIUM_OPERATOR_TAG} -cilium.hubble-relay-image=${HUBBLE_RELAY_IMAGE} -cilium.hubble-relay-tag=${HUBBLE_RELAY_TAG}'
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
