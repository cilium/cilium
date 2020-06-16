// This jenkinsfile sets tag based on git commit hash. Built docker image is tagged accordingly and pushed to local docker registry (living on the node)
// This allows multiple jobs to use the same registry.

@Library('cilium') _

pipeline {
    agent {
        label 'gke'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        GINKGO_TIMEOUT="180m"
        TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
        GOPATH="${WORKSPACE}"
        GKE_KEY=credentials('gke-key')
        TAG="${GIT_COMMIT}"
        HOME="${WORKSPACE}"
    }

    options {
        timeout(time: 260, unit: 'MINUTES')
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
                checkout scm
                sh 'mkdir -p ${PROJ_PATH}'
                sh 'ls -A | grep -v src | xargs mv -t ${PROJ_PATH}'
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
                        sh 'gcloud config set project cilium-ci'
                    }
                }
            }
        }
        stage('Make Cilium images and prepare gke cluster') {
            parallel {
                stage('Make Cilium images') {
                    steps {
                        sh 'cd ${TESTDIR}; ./make-images-push-to-local-registry.sh $(./print-node-ip.sh) ${TAG}'
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
                            script {
                                def name = readFile file: 'cluster-name'
                                currentBuild.displayName = currentBuild.displayName + " running on " + name
                            }
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
                CILIUM_IMAGE = """${sh(
                        returnStdout: true,
                        script: 'echo -n $(${TESTDIR}/print-node-ip.sh)/cilium/cilium:${TAG}'
                        )}"""
                CILIUM_OPERATOR_IMAGE= """${sh(
                        returnStdout: true,
                        script: 'echo -n $(${TESTDIR}/print-node-ip.sh)/cilium/operator-generic:${TAG}'
                        )}"""
                HUBBLE_RELAY_IMAGE= """${sh(
                        returnStdout: true,
                        script: 'echo -n $(${TESTDIR}/print-node-ip.sh)/cilium/hubble-relay:${TAG}'
                        )}"""
                K8S_VERSION= """${sh(
                        returnStdout: true,
                        script: 'cat ${TESTDIR}/gke/cluster-version'
                        )}"""
                FOCUS= """${sh(
                        returnStdout: true,
                        script: 'echo ${ghprbCommentBody} | sed -r "s/([^ ]* |^[^ ]*$)//" | sed "s/^$/K8s*/" | tr -d \'\n\''
                        )}"""
            }
            steps {
                dir("${TESTDIR}"){
                    sh 'env'
                    sh 'ginkgo --focus="${FOCUS}" -v -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.kubeconfig=${KUBECONFIG} -cilium.passCLIEnvironment=true -cilium.registry=$(./print-node-ip.sh) -cilium.image=${CILIUM_IMAGE} -cilium.operator-image=${CILIUM_OPERATOR_IMAGE} -cilium.hubble-relay-image=${HUBBLE_RELAY_IMAGE} -cilium.holdEnvironment=false'
                }
            }
            post {
                always {
                    sh 'cd ${TESTDIR}; ./archive_test_results_eks.sh || true'
                    archiveArtifacts artifacts: '**/*.zip'
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
            sh 'cd ${TESTDIR}; ./clean-local-registry-tag.sh $(./print-node-ip.sh) ${TAG} || true'
            sh 'cd ${TESTDIR}/gke; ./release-cluster.sh || true'
            cleanWs()
            sh '/usr/local/bin/cleanup || true'
        }
    }
}
