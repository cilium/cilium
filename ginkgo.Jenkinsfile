@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        VM_MEMORY = "4096"
        SERVER_BOX = "cilium/ubuntu"
        NETNEXT=setIfLabel("ci/net-next", "true", "false")
        GINKGO_TIMEOUT="300m"
    }

    options {
        timeout(time: 300, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
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
                        retry(3) {
                            timeout(time: 30, unit: 'MINUTES'){
                                sh 'cd ${TESTDIR}; vagrant destroy runtime --force'
                                sh 'cd ${TESTDIR}; vagrant up runtime --provision'
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
                stage('Boot vms K8s-1.11 net-next kubeproxy-free') {
                    environment {
                        TESTED_SUITE="k8s-1.11"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                        NETNEXT="true"
                        K8S_VERSION="1.11"
                        K8S_NODES="3"
                        NO_CILIUM_ON_NODE="k8s3"
                        KUBEPROXY="0"
                        KUBECONFIG="vagrant-kubeconfig"
                         //setting it here so we don't compile Cilium in vagrant nodes (already done on local node registry)
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        retry(3) {
                            timeout(time: 45, unit: 'MINUTES'){
                                dir("${TESTDIR}") {
                                    sh 'CILIUM_REGISTRY="$(./print-node-ip)" ./vagrant-ci-start.sh'
                                }
                            }
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8s 1.11 net-next vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('Boot vms K8s-1.17') {
                    environment {
                        TESTED_SUITE="k8s-1.17"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                        K8S_VERSION="1.17"
                        KUBECONFIG="vagrant-kubeconfig"
                    }
                    steps {
                        sh 'mkdir -p ${GOPATH}/src/github.com/cilium'
                        sh 'cp -a ${WORKSPACE}/${PROJ_PATH} ${GOPATH}/${PROJ_PATH}'
                        retry(3) {
                            timeout(time: 45, unit: 'MINUTES'){
                                dir("${TESTDIR}") {
                                    sh 'CILIUM_REGISTRY="$(./print-node-ip)" ./vagrant-ci-start.sh'
                                }
                            }
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'K8s 1.17 vm provisioning fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
            }
        }
        stage ("BDD-Test-PR"){
            options {
                timeout(time: 130, unit: 'MINUTES')
            }
            environment {
                FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
            }
            parallel {
                stage('BDD-Test-PR-runtime') {
                    environment {
                        TESTED_SUITE="runtime"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; ginkgo --focus="$(echo ${ghprbCommentBody} | sed -r "s/([^ ]* |^[^ ]*$)//" | sed "s/^$/Runtime*/" | sed "s/K8s.*/NoTests/")" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT}'
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
                stage('BDD-Test-PR-K8s-1.11-net-next-kubeproxy-free') {
                    environment {
                        TESTED_SUITE="k8s-1.11"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                        NETNEXT="true"
                        KUBECONFIG="${TESTDIR}/vagrant-kubeconfig"
                        K8S_VERSION="1.11"
                        K8S_NODES="3"
                        KUBEPROXY="0"
                        NO_CILIUM_ON_NODE="k8s3"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; HOME=${GOPATH} ginkgo --focus="$(echo ${ghprbCommentBody} | sed -r "s/([^ ]* |^[^ ]*$)//" | sed "s/^$/K8s*/" | sed "s/Runtime.*/NoTests/")" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.kubeconfig=${TESTDIR}/vagrant-kubeconfig -cilium.passCLIEnvironment=true -cilium.registry=$(./print-node-ip.sh)'
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
                                    currentBuild.displayName = 'K8s 1.11-net-next fail\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
                stage('BDD-Test-PR-K8s-1.17') {
                    environment {
                        TESTED_SUITE="k8s-1.17"
                        GOPATH="${WORKSPACE}/${TESTED_SUITE}-gopath"
                        TESTDIR="${GOPATH}/${PROJ_PATH}/test"
                        KUBECONFIG="${TESTDIR}/vagrant-kubeconfig"
                        K8S_VERSION="1.17"
                    }
                    steps {
                        sh 'cd ${TESTDIR}; HOME=${GOPATH} ginkgo --focus="$(echo ${ghprbCommentBody} | sed -r "s/([^ ]* |^[^ ]*$)//" | sed "s/^$/K8s*/" | sed "s/Runtime.*/NoTests/")" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.kubeconfig=${TESTDIR}/vagrant-kubeconfig -cilium.passCLIEnvironment=true -cilium.registry=$(./print-node-ip.sh)'
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
                                    currentBuild.displayName = 'K8s 1.17 fail\n' + currentBuild.displayName
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
            cleanWs()
            sh '/usr/local/bin/cleanup || true'
        }
    }
}
