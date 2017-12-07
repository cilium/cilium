pipeline {
    agent {
        label 'vagrant'
    }
    options {
        timeout(time: 120, unit: 'MINUTES')
        timestamps()
        disableConcurrentBuilds()
    }
    stages {
        stage('Boot VMs') {
            steps {
                sh './tests/start_vms'
            }
        }
        stage ('Tests') {
            environment {
                MEMORY = '4096'
                RUN_TEST_SUITE = '1'
            }
            steps {
                parallel(
                    "Print Environment": { sh 'env' },
                    "Runtime Tests": {
                         sh 'PROVISION=1 ./contrib/vagrant/start.sh'
                     },
                    "Runtime Tests with Envoy": {
                         sh 'CILIUM_USE_ENVOY=1 ./contrib/vagrant/start.sh'
                     },
                    "K8s multi node Tests": {
                         sh './tests/k8s/start.sh'
                    },
                    failFast: true
                )
            }
        }
    }
    post {
        always {
            sh './test/post_build_agent.sh || true'
            sh './tests/copy_files || true'
            archiveArtifacts artifacts: "cilium-files-runtime-${JOB_BASE_NAME}-${BUILD_NUMBER}.tar.gz", allowEmptyArchive: true
            sh './tests/k8s/copy_files || true'
            archiveArtifacts artifacts: "cilium-files-k8s-${JOB_BASE_NAME}-${BUILD_NUMBER}.tar.gz", allowEmptyArchive: true
            sh 'rm -rf ${WORKSPACE}/cilium-files*${JOB_BASE_NAME}-${BUILD_NUMBER}* ${WORKSPACE}/tests/cilium-files ${WORKSPACE}/tests/k8s/tests/cilium-files'
            sh 'ls'
            sh 'vagrant destroy -f'
            sh 'cd ./tests/k8s && vagrant destroy -f'
        }
    }
}
