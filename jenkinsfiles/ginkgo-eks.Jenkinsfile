@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        GINKGO_TIMEOUT="180m"
        TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
        GOPATH="${WORKSPACE}"
        AWS_ACCESS_KEY_ID=credentials('eks-secret-key-id')
        AWS_SECRET_ACCESS_KEY=credentials('eks-secret-key')
    }

    options {
        timeout(time: 240, unit: 'MINUTES')
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
        stage('Make Cilium images and prepare eks cluster') {
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
                        dir("${TESTDIR}/eks") {
                            sh './select-cluster.sh'
                        }
                    }
                    post {
                        unsuccessful {
                            sh 'cd ${TESTDIR}/eks; ./release-cluster.sh'
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
                KUBECONFIG="${TESTDIR}/eks/eks-kubeconfig"
                CNI_INTEGRATION="eks"
            }
            steps {
                dir("${TESTDIR}"){
                    sh 'CILIUM_IMAGE=$(./print-node-ip.sh)/cilium/cilium:latest CILIUM_OPERATOR_IMAGE=$(./print-node-ip.sh)/cilium/operator-generic:latest ginkgo --focus="$(echo ${ghprbCommentBody} | sed -r "s/([^ ]* |^[^ ]*$)//" | sed "s/^$/K8s/")" -v --failFast=${FAILFAST} -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.kubeconfig=${TESTDIR}/eks/eks-kubeconfig -cilium.passCLIEnvironment=true -cilium.registry=$(./print-node-ip.sh)'
                }
            }
            post {
                always {
                    sh 'cd ${TESTDIR}/eks; ./release-cluster.sh'
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
            sh 'cd ${TESTDIR}/eks; ./release-cluster.sh || true'
            cleanWs()
            sh '/usr/local/bin/cleanup || true'
        }
    }
}
