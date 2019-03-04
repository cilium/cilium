@Library('cilium') _

def triggerNetNext(){
    def causes = currentBuild.rawBuild.getCauses()
    println("Causes-->${causes}")
    println("Build->${currentBuild.rawBuild.class}")

    def ghprbCause = currentBuild.rawBuild.findCause(org.jenkinsci.plugins.ghprb.GhprbCause)
    println("GHPRBCause ---> ${ghprbCause}")

    def ghprbCauseB = currentBuild.rawBuild.getCause(org.jenkinsci.plugins.ghprb.GhprbCause.class)
    println("GHPRBCause ---> ${ghprbCauseB}")

    def UpstreamCause = currentBuild.rawBuild.getCause(hudson.model.Cause.UpstreamCause)
    if (UpstreamCause) {
        return
    }

    def jobparams = this.params.collect{
        if (it.key == "NETNEXT") {
            string(name: it.key, value: "true")
        }else {
            string(name: it.key, value: it.value)
        }
    }
    build(job: 'Cilium-PR-Ginkgo-Tests-Validated', parameters: jobparams, wait: false)
}

pipeline {
    agent {
        label 'eloy'
    }

    parameters {
        string(name: 'NETNEXT', defaultValue: 'false')
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        TESTDIR = "${WORKSPACE}/${PROJ_PATH}/"
        MEMORY = "4096"
        SERVER_BOX = "cilium/ubuntu"
    }

    options {
        timeout(time: 240, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Checkout') {
            options {
                timeout(time: 10, unit: 'MINUTES')
            }

            steps {
                Status("PENDING", "${env.JOB_NAME}")
                /* build(job: "Cilium-PR-Ginkgo-Tests-Validated") */
                triggerNetNext()
                BuildIfLabel('area/k8s', 'Cilium-PR-Kubernetes-Upstream')
                BuildIfLabel('integration/cni-flannel', 'Cilium-PR-K8s-Flannel')
                BuildIfLabel('area/k8s', 'Cilium-PR-Ginkgo-Tests-K8s')
                BuildIfLabel('area/documentation', 'Cilium-PR-Doc-Tests')
                sh 'env'
                sh 'rm -rf src; mkdir -p src/github.com/cilium'
                sh 'ln -s $WORKSPACE src/github.com/cilium/cilium'
                checkout scm
                sh '/usr/local/bin/cleanup || true'
            }
        }
        stage('Precheck') {
            when {
                environment name: 'NETNEXT', value: 'true'
            }

            options {
                timeout(time: 20, unit: 'MINUTES')
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
            }
        }
        stage('Boot VMs'){
            when {
                environment name: 'NETNEXT', value: 'true'
            }
            options {
                timeout(time: 30, unit: 'MINUTES')
            }
            environment {
                TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
            }
            steps {
                sh 'cd ${TESTDIR}; K8S_VERSION=1.8 vagrant up --no-provision'
                sh 'cd ${TESTDIR}; K8S_VERSION=1.13 vagrant up --no-provision'
            }
        }
        stage('BDD-Test-PR') {
            when {
                environment name: 'NETNEXT', value: 'true'
            }
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
                        "Runtime":{
                            sh 'cd ${TESTDIR}; vagrant provision runtime'
                            sh 'cd ${TESTDIR}; ginkgo --focus=" Runtime*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                        },
                        "K8s-1.8":{
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.8 vagrant provision k8s1-1.8; K8S_VERSION=1.8 vagrant provision k8s2-1.8'
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.8 ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
                        },
                        "K8s-1.13":{
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.13 vagrant provision k8s1-1.13; K8S_VERSION=1.13 vagrant provision k8s2-1.13'
                            sh 'cd ${TESTDIR}; K8S_VERSION=1.13 ginkgo --focus=" K8s*" -v --failFast=${FAILFAST} -- -cilium.provision=false'
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
            sh 'cd ${TESTDIR}/test/; K8S_VERSION=1.8 vagrant destroy -f || true'
            sh 'cd ${TESTDIR}/test/; K8S_VERSION=1.13 vagrant destroy -f || true'
            cleanWs()
        }
    }
}
