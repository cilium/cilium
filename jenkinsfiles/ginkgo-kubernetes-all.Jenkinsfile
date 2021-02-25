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
        VM_MEMORY = "4096"
        TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
        GOPATH="${WORKSPACE}"
        SERVER_BOX = "cilium/ubuntu"
        FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
        CNI_INTEGRATION=setIfLabel("integration/cni-flannel", "FLANNEL", "")
        HOST_FIREWALL=setIfLabel("ci/host-firewall", "1", "0")
        GINKGO_TIMEOUT="118m"
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
                script: 'if [ "${run_with_race_detection}" = "" ]; then echo -n "scratch"; else echo -n "quay.io/cilium/cilium-runtime:acc75dac6c3f45e31d074cc7d1ae8ff33c140a6b@sha256:3e6f4b5fdbc0ff3b80af7a323268dd30c02678b829f88e27035bdc06017b4e81"; fi'
            )}"""
        RUN_QUARANTINED="""${sh(
                returnStdout: true,
                script: 'if [ "${RunQuarantined}" = "" ]; then echo -n "false"; else echo -n "${RunQuarantined}"; fi'
            )}"""
		KUBECONFIG="vagrant-kubeconfig"
    }

    options {
        timeout(time: 540, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
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
                sh 'cd ${TESTDIR}; ./make-images-push-to-local-registry.sh $(./print-node-ip.sh) latest'
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
        stage('Copy code and boot VMs 1.{17,18}'){

            options {
                timeout(time: 60, unit: 'MINUTES')
            }

            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }

            parallel {
                stage('Boot vms 1.17') {
                    environment {
                        K8S_VERSION="1.17"
                        GOPATH="${WORKSPACE}/${K8S_VERSION}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        withCredentials([usernamePassword(credentialsId: 'CILIUM_BOT_DUMMY', usernameVariable: 'DOCKER_LOGIN', passwordVariable: 'DOCKER_PASSWORD')]) {
                            retry(3) {
                                timeout(time: 30, unit: 'MINUTES'){
                                    dir("${TESTDIR}") {
                                        sh 'CILIUM_REGISTRY="$(./print-node-ip.sh)" ./vagrant-ci-start.sh'
                                    }
                                }
                            }
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.17 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('Boot vms 1.18') {
                    environment {
                        K8S_VERSION="1.18"
                        GOPATH="${WORKSPACE}/${K8S_VERSION}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        withCredentials([usernamePassword(credentialsId: 'CILIUM_BOT_DUMMY', usernameVariable: 'DOCKER_LOGIN', passwordVariable: 'DOCKER_PASSWORD')]) {
                            retry(3) {
                                timeout(time: 30, unit: 'MINUTES'){
                                    dir("${TESTDIR}") {
                                        sh 'CILIUM_REGISTRY="$(./print-node-ip.sh)" ./vagrant-ci-start.sh'
                                    }
                                }
                            }
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.18 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
            }
        }
        stage('BDD-Test-k8s-1.17-and-1.18') {
            environment {
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
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
                KUBECONFIG="${TESTDIR}/vagrant-kubeconfig"
            }
            options {
                timeout(time: 300, unit: 'MINUTES')
            }
            parallel {
                stage('BDD-Test-k8s-1.17') {
                    environment {
                        K8S_VERSION="1.17"
                        GOPATH="${WORKSPACE}/${K8S_VERSION}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; ginkgo --focus="K8s" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.runQuarantined=${RUN_QUARANTINED} -cilium.image=${CILIUM_IMAGE} -cilium.tag=${CILIUM_TAG} -cilium.operator-image=${CILIUM_OPERATOR_IMAGE} -cilium.operator-tag=${CILIUM_OPERATOR_TAG} -cilium.hubble-relay-image=${HUBBLE_RELAY_IMAGE} -cilium.hubble-relay-tag=${HUBBLE_RELAY_TAG} -cilium.kubeconfig=${TESTDIR}/vagrant-kubeconfig -cilium.passCLIEnvironment=true'
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
                                    currentBuild.displayName = 'K8s 1.17 tests fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('BDD-Test-k8s-1.18') {
                    environment {
                        K8S_VERSION="1.18"
                        GOPATH="${WORKSPACE}/${K8S_VERSION}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; ginkgo --focus="K8s" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.runQuarantined=${RUN_QUARANTINED} -cilium.image=${CILIUM_IMAGE} -cilium.tag=${CILIUM_TAG} -cilium.operator-image=${CILIUM_OPERATOR_IMAGE} -cilium.operator-tag=${CILIUM_OPERATOR_TAG} -cilium.hubble-relay-image=${HUBBLE_RELAY_IMAGE} -cilium.hubble-relay-tag=${HUBBLE_RELAY_TAG} -cilium.kubeconfig=${TESTDIR}/vagrant-kubeconfig -cilium.passCLIEnvironment=true'
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
                                    currentBuild.displayName = 'K8s 1.18 tests fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
            }
        }
        stage('Copy code and boot VMs 1.{19,20}'){

            options {
                timeout(time: 60, unit: 'MINUTES')
            }

            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }

            parallel {
                stage('Boot vms 1.19') {
                    environment {
                        K8S_VERSION="1.19"
                        GOPATH="${WORKSPACE}/${K8S_VERSION}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        withCredentials([usernamePassword(credentialsId: 'CILIUM_BOT_DUMMY', usernameVariable: 'DOCKER_LOGIN', passwordVariable: 'DOCKER_PASSWORD')]) {
                            retry(3) {
                                timeout(time: 30, unit: 'MINUTES'){
                                    dir("${TESTDIR}") {
                                        sh 'CILIUM_REGISTRY="$(./print-node-ip.sh)" ./vagrant-ci-start.sh'
                                    }
                                }
                            }
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.19 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('Boot vms 1.20') {
                    environment {
                        K8S_VERSION="1.20"
                        GOPATH="${WORKSPACE}/${K8S_VERSION}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        withCredentials([usernamePassword(credentialsId: 'CILIUM_BOT_DUMMY', usernameVariable: 'DOCKER_LOGIN', passwordVariable: 'DOCKER_PASSWORD')]) {
                            retry(3) {
                                timeout(time: 30, unit: 'MINUTES'){
                                    dir("${TESTDIR}") {
                                        sh 'CILIUM_REGISTRY="$(./print-node-ip.sh)" ./vagrant-ci-start.sh'
                                    }
                                }
                            }
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8S 1.20 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
            }
        }
        stage('BDD-Test-k8s-1.19-and-1.20') {
            environment {
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
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
                KUBECONFIG="${TESTDIR}/vagrant-kubeconfig"
            }
            options {
                timeout(time: 180, unit: 'MINUTES')
            }
            parallel {
                stage('BDD-Test-k8s-1.19') {
                    environment {
                        K8S_VERSION="1.19"
                        GOPATH="${WORKSPACE}/${K8S_VERSION}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; ginkgo --focus="K8s" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.runQuarantined=${RUN_QUARANTINED} -cilium.image=${CILIUM_IMAGE} -cilium.tag=${CILIUM_TAG} -cilium.operator-image=${CILIUM_OPERATOR_IMAGE} -cilium.operator-tag=${CILIUM_OPERATOR_TAG} -cilium.hubble-relay-image=${HUBBLE_RELAY_IMAGE} -cilium.hubble-relay-tag=${HUBBLE_RELAY_TAG} -cilium.kubeconfig=${TESTDIR}/vagrant-kubeconfig -cilium.passCLIEnvironment=true'
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
                                    currentBuild.displayName = 'K8s 1.19 tests fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('BDD-Test-k8s-1.20') {
                    environment {
                        K8S_VERSION="1.20"
                        GOPATH="${WORKSPACE}/${K8S_VERSION}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; ginkgo --focus="K8s" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.runQuarantined=${RUN_QUARANTINED} -cilium.image=${CILIUM_IMAGE} -cilium.tag=${CILIUM_TAG} -cilium.operator-image=${CILIUM_OPERATOR_IMAGE} -cilium.operator-tag=${CILIUM_OPERATOR_TAG} -cilium.hubble-relay-image=${HUBBLE_RELAY_IMAGE} -cilium.hubble-relay-tag=${HUBBLE_RELAY_TAG} -cilium.kubeconfig=${TESTDIR}/vagrant-kubeconfig -cilium.passCLIEnvironment=true'
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
                                    currentBuild.displayName = 'K8s 1.20 tests fail\n' + currentBuild.displayName
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
            sh 'lscpu'
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
