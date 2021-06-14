@Library('cilium') _

pipeline {
    agent {
        label 'baremetal'
    }

    environment {
        PROJ_PATH = "src/github.com/cilium/cilium"
        TESTDIR="${WORKSPACE}/${PROJ_PATH}/test"
        VM_MEMORY = "5120"
        K8S_VERSION="1.21"
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
                not {environment name: 'GIT_BRANCH', value: 'origin/master'}
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
                Status("PENDING", "${env.JOB_NAME}")
                checkout scm
                sh 'mkdir -p ${PROJ_PATH}'
                sh 'ls -A | grep -v src | xargs mv -t ${PROJ_PATH}'
                sh '/usr/local/bin/cleanup || true'
            }
        }
        stage('Set programmatic env vars') {
            steps {
                script {
                    if (env.ghprbActualCommit?.trim()) {
                        env.DOCKER_TAG = env.ghprbActualCommit
                    } else {
                        env.DOCKER_TAG = env.GIT_COMMIT
                    }
                    if (env.run_with_race_detection?.trim()) {
                        env.DOCKER_TAG = env.DOCKER_TAG + "-race"
                        env.RACE = 1
                        env.LOCKDEBUG = 1
                        env.BASE_IMAGE = "quay.io/cilium/cilium-runtime:13fc53394a676909ee74fbde1ba9de485e01bd34@sha256:95a5bd7b5bc73b1cbdf9a3704cb3389ca1857e283ae38941539214cbae7c6dcd"
                    }
                }
            }
        }
        stage('Preload vagrant boxes'){
            options {
                timeout(time: 20, unit: 'MINUTES')
            }

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

            steps {
                sh 'cd ${TESTDIR}; vagrant ssh k8s1-${K8S_VERSION} -c "cd /home/vagrant/go/${PROJ_PATH}; sudo ./test/kubernetes-test.sh ${DOCKER_TAG}"'
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
        success {
            Status("SUCCESS", "$JOB_BASE_NAME")
        }
        failure {
            Status("FAILURE", "$JOB_BASE_NAME")
        }
    }
}
