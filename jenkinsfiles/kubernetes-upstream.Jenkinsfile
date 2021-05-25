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
                        env.BASE_IMAGE = "quay.io/cilium/cilium-runtime:8fe001a11f25ad9e6676c19b0431f83c893fbab4@sha256:921ab4bf310f562ce7d4aea1f5c2bc8651f273f1a93b36c71b9cb9954869ef68"
                    }

                    /* Hack:
                    Force preload of a specific Vagrant box image from Vagrant
                    cache depending on chosen Kernel.

                    Context:
                    The `add_vagrant_box` script preloads Vagrant boxes from our
                    Vagrant cache over at http://vagrant-cache.ci.cilium.io/.
                    By default it preloads a list of hardedcoded boxes.
                    An optional arg can be provided to preload a specific box.
                    Problem is the box to preload is only known at Vagrant
                    boot time (determined in Vagrantfile), hence this hack.
                    */
                    switch(env.JobKernelVersion) {
                        case "49":
                            env.PRELOAD_BOX = "v49_SERVER"
                            break
                        case "54":
                            env.PRELOAD_BOX = "v419_SERVER"
                            break
                        case "419":
                            env.PRELOAD_BOX = "v54_SERVER"
                            break
                        case "net-next":
                            env.PRELOAD_BOX = "NETNEXT_SERVER"
                            break
                        default:
                            env.PRELOAD_BOX = "v419_SERVER"
                            break
                    }
                }
            }
        }
        stage('Preload vagrant boxes'){
            options {
                timeout(time: 20, unit: 'MINUTES')
            }

            steps {
                sh '/usr/local/bin/add_vagrant_box ${WORKSPACE}/${PROJ_PATH}/vagrant_box_defaults.rb ${PRELOAD_BOX}'
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
