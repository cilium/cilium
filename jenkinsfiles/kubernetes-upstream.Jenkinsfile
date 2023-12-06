@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
        VM_MEMORY = "5120"
        K8S_VERSION="1.26"
        KERNEL="419"
        SERVER_BOX = "cilium/ubuntu-4-19"
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
            steps {
                sh 'env'
                checkout scm
                sh 'mkdir -p ${PROJ_PATH}'
                sh 'ls -A | grep -v src | xargs mv -t ${PROJ_PATH}'
                sh '/usr/local/bin/cleanup || true'
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
                        env.BASE_IMAGE = "quay.io/cilium/cilium-runtime:d0d7d1fbbda711f5054bb21a992dc65470025fea@sha256:b18421e0c8a9d5ddc8e534b43736ffbdcc2343d5a29fe51942686a8ba9c957b0"
                    }
                }
            }
        }
        stage('Preload vagrant boxes'){
            steps {
                sh '/usr/local/bin/add_vagrant_box ${WORKSPACE}/${PROJ_PATH}/vagrant_box_defaults.rb'
            }
        }
        stage('Boot VMs'){
            options {
                timeout(time: 70, unit: 'MINUTES')
            }

            steps {
                retry(3){
                    sh 'cd ${TESTDIR}; vagrant destroy k8s1-${K8S_VERSION} --force'
                    sh 'cd ${TESTDIR}; vagrant destroy k8s2-${K8S_VERSION} --force'
                    sh 'cd ${TESTDIR}; CILIUM_REGISTRY=quay.io timeout 20m vagrant up k8s1-${K8S_VERSION} k8s2-${K8S_VERSION}'
                }
            }
        }

        stage('BDD-tests'){
            options {
                timeout(time: 150, unit: 'MINUTES')
            }

            environment {
                POLL_TIMEOUT_SECONDS=300
            }

            steps {
                sh 'cd ${TESTDIR}; vagrant ssh k8s1-${K8S_VERSION} -c "cd /home/vagrant/go/${PROJ_PATH}; sudo ./test/kubernetes-test.sh ${IMAGE_REGISTRY} ${DOCKER_TAG}"'
            }
        }

        stage('Netperf tests'){

            when {
                environment name: 'GIT_BRANCH', value: 'origin/master'
            }

            options {
                timeout(time: 300, unit: 'MINUTES')
            }

            environment {
                PROMETHEUS_URL="https://metrics.cilium.io/metrics/job/upstream_job"
                PROMETHEUS=credentials("metrics")
            }

            steps {
                sh '''
                    cd ${TESTDIR}; vagrant ssh k8s1-${K8S_VERSION} -c "
                        cd /home/vagrant/go/${PROJ_PATH}/test;
                        ./kubernetes-netperftest.sh '$PROMETHEUS_URL' '$PROMETHEUS_USR' '$PROMETHEUS_PSW'"
                '''
            }
        }
    }
    post {
        always {
            sh 'lscpu'
            sh 'cd ${TESTDIR}; K8S_VERSION=${K8S_VERSION} vagrant destroy -f || true'
            cleanWs()
            sh '/usr/local/bin/cleanup || true'
        }
    }
}
