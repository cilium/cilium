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
    }

    options {
        timeout(time: 300, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Set build name') {
            when {
                not {
                    anyOf {
                        environment name: 'ghprbPullTitle', value: null
                        environment name: 'ghprbPullLink', value: null
                    }
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
                timeout(time: 20, unit: 'MINUTES')
            }

            steps {
                sh 'env'
                checkout scm
                sh 'mkdir -p ${PROJ_PATH}'
                sh 'ls -A | grep -v src | xargs mv -t ${PROJ_PATH}'
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
        stage('Set programmatic env vars') {
            steps {
                script {
                    env.IMAGE_REGISTRY = sh script: 'echo -n ${JobImageRegistry:-quay.io/cilium}', returnStdout: true

                    if (env.ghprbActualCommit?.trim()) {
                        env.DOCKER_TAG = env.ghprbActualCommit
                    } else {
                        env.DOCKER_TAG = env.GIT_COMMIT
                    }
                    if (env.run_with_race_detection?.trim()) {
                        env.DOCKER_TAG = env.DOCKER_TAG + "-race"
                        env.RACE = 1
                        env.LOCKDEBUG = 1
                        env.BASE_IMAGE = "quay.io/cilium/cilium-runtime:ad71fe7980638d9b7d4c57fc07604cea9a0a1371@sha256:70972d83f30c8204564451ad57e338a45cf9ca140c5a00310c91c9b29a1d851e"
                    }
                }
            }
        }
        stage('Wait for Cilium images and prepare gke cluster') {
            parallel {
                stage('Wait for images') {
                    options {
                        timeout(time: 20, unit: 'MINUTES')
                    }
                    steps {
                        retry(25) {
                            sleep(time: 60)
                            sh 'docker manifest inspect ${IMAGE_REGISTRY}/cilium-ci:${DOCKER_TAG}} &> /dev/null'
                            sh 'docker manifest inspect ${IMAGE_REGISTRY}/operator-generic-ci:${DOCKER_TAG}} &> /dev/null'
                            sh 'docker manifest inspect ${IMAGE_REGISTRY}/hubble-relay-ci:${DOCKER_TAG}} &> /dev/null'
                        }
                    }
                }
                stage ("Create cluster"){
                    options {
                        timeout(time: 20, unit: 'MINUTES')
                    }
                    environment {
                        FAILFAST=setIfLabel("ci/fail-fast", "true", "false")
                    }
                    steps {
                        dir("${TESTDIR}/gke") {
                            script {
                                sh './create-cluster.sh "' + currentBuild.fullProjectName.toLowerCase() + '-' + currentBuild.id + '"'
                                def name = readFile file: 'cluster-name'
                                currentBuild.displayName = currentBuild.displayName + " running on " + name
                            }
                        }
                    }
                    post {
                        unsuccessful {
                            script {
                                if  (!currentBuild.displayName.contains('fail')) {
                                    currentBuild.displayName = 'cluster creation failed\n' + currentBuild.displayName
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
                CILIUM_IMAGE = "${IMAGE_REGISTRY}/cilium-ci"
                CILIUM_TAG = "${DOCKER_TAG}"
                CILIUM_OPERATOR_IMAGE= "${IMAGE_REGISTRY}/operator"
                CILIUM_OPERATOR_TAG = "${DOCKER_TAG}"
                HUBBLE_RELAY_IMAGE= "${IMAGE_REGISTRY}/hubble-relay-ci"
                HUBBLE_RELAY_TAG = "${DOCKER_TAG}"
                K8S_VERSION= """${sh(
                        returnStdout: true,
                        script: 'cat ${TESTDIR}/gke/cluster-version'
                        )}"""
                FOCUS= """${sh(
                        returnStdout: true,
                        script: 'echo ${ghprbCommentBody} | sed -r "s/([^ ]* |^[^ ]*$)//" | sed "s/^$/K8s*/" | tr -d \'\n\''
                        )}"""
                KERNEL="419"
                NATIVE_CIDR= """${sh(
                        returnStdout: true,
                        script: 'cat ${TESTDIR}/gke/cluster-cidr | tr -d \'\n\''
                        )}"""
            }
            steps {
                dir("${TESTDIR}"){
                    sh 'env'
                    sh 'ginkgo --focus="${FOCUS}" --tags=integration_tests -v -- -cilium.provision=false -cilium.timeout=${GINKGO_TIMEOUT} -cilium.kubeconfig=${KUBECONFIG} -cilium.passCLIEnvironment=true -cilium.image=${CILIUM_IMAGE} -cilium.tag=${CILIUM_TAG} -cilium.operator-image=${CILIUM_OPERATOR_IMAGE} -cilium.operator-tag=${CILIUM_OPERATOR_TAG} -cilium.hubble-relay-image=${HUBBLE_RELAY_IMAGE} -cilium.hubble-relay-tag=${HUBBLE_RELAY_TAG} -cilium.holdEnvironment=false -cilium.runQuarantined=${RUN_QUARANTINED} -cilium.operator-suffix="-ci"'
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
            sh 'cd ${TESTDIR}/gke; ./release-cluster.sh || true'
            cleanWs()
            sh '/usr/local/bin/cleanup || true'
        }
    }
}
