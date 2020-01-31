@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        TESTDIR = "${WORKSPACE}/${PROJ_PATH}/"
        VM_MEMORY = "4096"
        SERVER_BOX = "cilium/ubuntu"
        NETNEXT=setIfLabel("ci/net-next", "true", "false")
        CNI_INTEGRATION="flannel"
        GINKGO_TIMEOUT="73m"
    }

    options {
        timeout(time: 240, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Checkout') {
            options {
                timeout(time: 20, unit: 'MINUTES')
            }

            steps {
                Status("PENDING", "${env.JOB_NAME}")
                sh 'env'
                sh 'rm -rf src; mkdir -p src/github.com/cilium'
                sh 'ln -s $WORKSPACE src/github.com/cilium/cilium'
                checkout scm
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
        stage('Boot VMs'){
            options {
                timeout(time: 60, unit: 'MINUTES')
            }
            environment {
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            steps {
                retry(3){
                    timeout(time: 20, unit: 'MINUTES'){
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.10 vagrant destroy --force'
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.13 vagrant destroy --force'
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.10 vagrant up --no-provision'
                        sh 'cd ${TESTDIR}; K8S_VERSION=1.13 vagrant up --no-provision'
                    }
                }
            }
        }
        stage('BDD-Test-PR') {
            environment {
                GOPATH="${WORKSPACE}"
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
                FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")

            }

            options {
                timeout(time: 75, unit: 'MINUTES')
            }

            steps {
                script {
                    parallel(
                        "K8s-1.10":{
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.10 vagrant provision k8s1-1.10; K8S_VERSION=1.10 vagrant provision k8s2-1.10'
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.10 ginkgo  --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT}'
                        },
                        "K8s-1.13":{
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.13 vagrant provision k8s1-1.13; K8S_VERSION=1.13 vagrant provision k8s2-1.13'
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.13 ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT}'
                        },
                        failFast: "${FAILFAST}".toBoolean()
                    )
                }
            }
            post {
                always {
                    // Temporary workaround to test cleanup
                    // rm -rf ${GOPATH}/src/github.com/cilium/cilium
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
            sh 'cd ${TESTDIR}/test/; K8S_VERSION=1.10 vagrant destroy -f || true'
            sh 'cd ${TESTDIR}/test/; K8S_VERSION=1.13 vagrant destroy -f || true'
            cleanWs()
            sh '/usr/local/bin/cleanup || true'
        }
        success {
            Status("SUCCESS", "$JOB_BASE_NAME")
        }
        failure {
            Status("FAILURE", "$JOB_BASE_NAME")
        }
    }
}
