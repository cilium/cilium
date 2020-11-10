@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        GINKGO_TIMEOUT="108m"
        TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
        GOPATH="${WORKSPACE}"
        GKE_KEY=credentials('gke-key')
    }

    options {
        timeout(time: 260, unit: 'MINUTES')
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
                checkout scm
                sh 'mkdir -p ${PROJ_PATH}'
                sh 'ls -A | grep -v src | xargs mv -t ${PROJ_PATH}'
                sh '/usr/local/bin/cleanup || true'
            }
        }
        stage('Precheck') {
            options {
                timeout(time: 20, unit: 'MINUTES')
            }

            steps {
               sh "cd ${WORKSPACE}/${PROJ_PATH}; make jenkins-precheck"
            }
            post {
               always {
                   sh "cd ${WORKSPACE}/${PROJ_PATH}; make clean-jenkins-precheck || true"
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
        stage('Authenticate in gke') {
            steps {
                dir("/tmp") {
                    withCredentials([file(credentialsId: 'gke-key', variable: 'KEY_PATH')]) {
                        sh 'gcloud auth activate-service-account --key-file ${KEY_PATH}'
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
        stage('Make Cilium images and prepare gke cluster') {
            parallel {
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
                stage ("Select cluster and scale it"){
                    options {
                        timeout(time: 20, unit: 'MINUTES')
                    }
                    environment {
                        FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                    }
                    steps {
                        dir("${TESTDIR}/gke") {
                            sh './select-cluster.sh'
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'Scaling cluster failed\n' + currentBuild.displayName
                                }
                            }
                        }
                    }
                }
            }
        }
        stage ("BDD-Test-PR"){
            options {
                timeout(time: 250, unit: 'MINUTES')
            }
            environment {
                FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                CONTAINER_RUNTIME=setIfLabel("area/containerd", "containerd", "docker")
                KUBECONFIG="${TESTDIR}/gke/gke-kubeconfig"
                CNI_INTEGRATION="gke"
            }
            steps {
                dir("${TESTDIR}"){
                    sh 'K8S_VERSION=$(${TESTDIR}/gke/get-cluster-version.sh) CILIUM_IMAGE=$(./print-node-ip.sh)/cilium/cilium:latest CILIUM_OPERATOR_IMAGE=$(./print-node-ip.sh)/cilium/operator:latest ginkgo --focus="$(echo ${ghprbCommentBody} | sed -r "s/([^ ]* |^[^ ]*$)//" | sed "s/^$/K8s*/")" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.kubeconfig=${TESTDIR}/gke/gke-kubeconfig -cilium.passCLIEnvironment=true -cilium.registry=$(./print-node-ip.sh)'
                }
            }
            post {
                always {
                    sh 'cd ${TESTDIR}; ./archive_test_results_eks.sh || true'
                    archiveArtifacts artifacts: 'src/github.com/cilium/cilium/*.zip'
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
            sh 'cd ${TESTDIR}/gke; ./release-cluster.sh || true'
            cleanWs()
            sh '/usr/local/bin/cleanup || true'
        }
    }
}
