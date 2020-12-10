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
        stage('Start docker registry for build') {
            steps{
                sh 'cd ${TESTDIR}/gke; ./start-registry.sh'
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
                    steps {
                        sh 'cd ${TESTDIR}; ./make-images-push-to-local-registry.sh $(gke/registry-ip.sh) ${TAG} "--no-cache"'
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
                            retry(3){
                                sh './release-cluster.sh || true'
                                sh './select-cluster.sh'
                            }
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
                        script: 'echo -n $(${TESTDIR}/gke/registry-ip.sh)/cilium/cilium'
                        )}"""
                CILIUM_TAG = """${sh(
                        returnStdout: true,
                        script: 'echo -n ${TAG}'
                        )}"""
                CILIUM_OPERATOR_IMAGE= """${sh(
                        returnStdout: true,
                        script: 'echo -n $(${TESTDIR}/gke/registry-ip.sh)/cilium/operator'
                        )}"""
                CILIUM_OPERATOR_TAG = """${sh(
                        returnStdout: true,
                        script: 'echo -n ${TAG}'
                        )}"""
                HUBBLE_RELAY_IMAGE= """${sh(
                        returnStdout: true,
                        script: 'echo -n $(${TESTDIR}/gke/registry-ip.sh)/cilium/hubble-relay'
                        )}"""
                HUBBLE_RELAY_TAG = """${sh(
                        returnStdout: true,
                        script: 'echo -n ${TAG}'
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
                    sh 'ginkgo --focus="${FOCUS}" -v -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.kubeconfig=${KUBECONFIG} -cilium.passCLIEnvironment=true -cilium.image=${CILIUM_IMAGE} -cilium.tag=${CILIUM_TAG} -cilium.operator-image=${CILIUM_OPERATOR_IMAGE} -cilium.operator-tag=${CILIUM_OPERATOR_TAG} -cilium.hubble-relay-image=${HUBBLE_RELAY_IMAGE} -cilium.hubble-relay-tag=${HUBBLE_RELAY_TAG} -cilium.holdEnvironment=false -cilium.runQuarantined=${RUN_QUARANTINED}'
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
            sh 'cd ${TESTDIR}/gke; ./stop-registry.sh || true'
            sh 'cd ${TESTDIR}/gke; ./release-cluster.sh || true'
            cleanWs()
            sh '/usr/local/bin/cleanup || true'
        }
    }
}
