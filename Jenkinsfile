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
        stage ('Tests') {
            environment {
                MEMORY = '4096'
                RUN_TEST_SUITE = '1'
            }
            steps {
     		           
                parallel(
                    "Print Environment": { sh 'env' },
                    "Runtime Tests": {
                         // Make sure that VMs from prior runs are cleaned up in case something went wrong in a prior build.
                         sh 'vagrant destroy -f || true'
                         sh './contrib/vagrant/start.sh'
                     },
                    "Runtime Tests with Envoy": {
                         // Make sure that VMs from prior runs are cleaned up in case something went wrong in a prior build.
                         sh 'CILIUM_USE_ENVOY=1 vagrant destroy -f || true'
                         sh 'CILIUM_USE_ENVOY=1 ./contrib/vagrant/start.sh'
                     },
                    "K8s multi node Tests": {
                         sh 'cd ./tests/k8s && vagrant destroy -f || true'
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
            sh 'CILIUM_USE_ENVOY=1 vagrant destroy -f'
            sh 'cd ./tests/k8s && vagrant destroy -f'
        }
    }
}
