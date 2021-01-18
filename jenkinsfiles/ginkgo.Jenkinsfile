@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        VM_MEMORY = "4096"
        SERVER_BOX = "cilium/ubuntu"
        NETNEXT=setIfLabel("ci/net-next", "1", "0")
        GINKGO_TIMEOUT="360m"
    }

    options {
        timeout(time: 360, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Set build name') {
            when {
                allOf {
                    not {environment name: 'GIT_BRANCH', value: 'origin/master'};
                    not {environment name: 'GIT_BRANCH', value: 'master'};
                    not {branch 'master'}
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
                BuildIfLabel('area/k8s', 'Cilium-PR-Kubernetes-Upstream')
                BuildIfLabel('integration/cni-flannel', 'Cilium-PR-K8s-Flannel')
                BuildIfLabel('area/k8s', 'Cilium-PR-Ginkgo-Tests-K8s')
                BuildIfLabel('area/documentation', 'Cilium-PR-Doc-Tests')
                sh 'env'
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
        stage ("Copy code and boot vms"){
            options {
                timeout(time: 120, unit: 'MINUTES')
            }

            environment {
                FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
            }
            parallel {
                stage('Boot vms runtime') {
                    environment {
                        TESTED_SUITE="runtime"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        withCredentials([usernamePassword(credentialsId: 'CILIUM_BOT_DUMMY', usernameVariable: 'DOCKER_LOGIN', passwordVariable: 'DOCKER_PASSWORD')]) {
                            retry(3) {
                                sh 'cd ${TESTDIR}; vagrant destroy runtime --force'
                                sh 'cd ${TESTDIR}; timeout 30m vagrant up runtime --provision'
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
                stage('Boot vms K8s-1.13 net-next kubeproxy-free') {
                    environment {
                        TESTED_SUITE="k8s-1.13"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                        NETNEXT="1"
                        K8S_VERSION="1.13"
                        K8S_NODES="3"
                        NO_CILIUM_ON_NODE="k8s3"
                        KUBEPROXY="1"
                        KUBECONFIG="vagrant-kubeconfig"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        withCredentials([usernamePassword(credentialsId: 'CILIUM_BOT_DUMMY', usernameVariable: 'DOCKER_LOGIN', passwordVariable: 'DOCKER_PASSWORD')]) {
                            retry(3) {
                                dir("${TESTDIR}") {
                                    sh 'CILIUM_REGISTRY="$(./print-node-ip.sh)" timeout 45m ./vagrant-ci-start.sh'
                                }
                            }
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8s 1.13 net-next vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('Boot vms K8s-1.20') {
                    environment {
                        TESTED_SUITE="k8s-1.20"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                        K8S_VERSION="1.20"
                        KUBECONFIG="vagrant-kubeconfig"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        withCredentials([usernamePassword(credentialsId: 'CILIUM_BOT_DUMMY', usernameVariable: 'DOCKER_LOGIN', passwordVariable: 'DOCKER_PASSWORD')]) {
                            retry(3) {
                                dir("${TESTDIR}") {
                                    sh 'CILIUM_REGISTRY="$(./print-node-ip.sh)" timeout 45m ./vagrant-ci-start.sh'
                                }
                            }
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8s 1.20 vm provisioning fail\n' + currentBuild.displayName
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
                FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
                CILIUM_IMAGE = """${sh(
                        returnStdout: true,
                        script: 'echo -n $(${WORKSPACE}/${PROJ_PATH}/test/print-node-ip.sh)/cilium/cilium'
                        )}"""
                CILIUM_TAG = "latest"
                CILIUM_OPERATOR_IMAGE= """${sh(
                        returnStdout: true,
                        script: 'echo -n $(${WORKSPACE}/${PROJ_PATH}/test/print-node-ip.sh)/cilium/operator'
                        )}"""
                CILIUM_OPERATOR_TAG = "latest"
                HUBBLE_RELAY_IMAGE= """${sh(
                        returnStdout: true,
                        script: 'echo -n $(${WORKSPACE}/${PROJ_PATH}/test/print-node-ip.sh)/cilium/hubble-relay'
                        )}"""
                HUBBLE_RELAY_TAG = "latest"
            }
            parallel {
                stage('BDD-Test-PR-runtime') {
                    environment {
                        TESTED_SUITE="runtime"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; ginkgo --focus="$(echo ${ghprbCommentBody} | sed -r "s/([^ ]* |^[^ ]*$)//" | sed "s/^$/Runtime/" | sed "s/K8s.*/NoTests/")" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT}'
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
                                    currentBuild.displayName = 'Runtime tests fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('BDD-Test-PR-K8s-1.13-net-next-kubeproxy-free') {
                    environment {
                        TESTED_SUITE="k8s-1.13"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                        NETNEXT="1"
                        KUBECONFIG="${TESTDIR}/vagrant-kubeconfig"
                        K8S_VERSION="1.13"
                        K8S_NODES="3"
                        KUBEPROXY="1"
                        NO_CILIUM_ON_NODE="k8s3"
                        HOST_FIREWALL=setIfLabel("ci/host-firewall", "1", "0")
                    }
                    steps {
                        sh 'cd ${TESTDIR}; HOME=${GOPATH} ginkgo --focus="$(echo ${ghprbCommentBody} | sed -r "s/([^ ]* |^[^ ]*$)//" | sed "s/^$/K8s/" | sed "s/Runtime.*/NoTests/")" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.kubeconfig=${TESTDIR}/vagrant-kubeconfig -cilium.passCLIEnvironment=true -cilium.image=${CILIUM_IMAGE} -cilium.tag=${CILIUM_TAG} -cilium.operator-image=${CILIUM_OPERATOR_IMAGE} -cilium.operator-tag=${CILIUM_OPERATOR_TAG} -cilium.hubble-relay-image=${HUBBLE_RELAY_IMAGE} -cilium.hubble-relay-tag=${HUBBLE_RELAY_TAG}'
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
                                    currentBuild.displayName = 'K8s 1.13-net-next fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('BDD-Test-PR-K8s-1.20') {
                    environment {
                        TESTED_SUITE="k8s-1.20"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                        KUBECONFIG="${TESTDIR}/vagrant-kubeconfig"
                        K8S_VERSION="1.20"
                        HOST_FIREWALL=setIfLabel("ci/host-firewall", "1", "0")
                    }
                    steps {
                        sh 'cd ${TESTDIR}; HOME=${GOPATH} ginkgo --focus="$(echo ${ghprbCommentBody} | sed -r "s/([^ ]* |^[^ ]*$)//" | sed "s/^$/K8s/" | sed "s/Runtime.*/NoTests/")" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.kubeconfig=${TESTDIR}/vagrant-kubeconfig -cilium.passCLIEnvironment=true -cilium.image=${CILIUM_IMAGE} -cilium.tag=${CILIUM_TAG} -cilium.operator-image=${CILIUM_OPERATOR_IMAGE} -cilium.operator-tag=${CILIUM_OPERATOR_TAG} -cilium.hubble-relay-image=${HUBBLE_RELAY_IMAGE} -cilium.hubble-relay-tag=${HUBBLE_RELAY_TAG}'
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
                                    currentBuild.displayName = 'K8s 1.20 fail\n' + currentBuild.displayName
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
