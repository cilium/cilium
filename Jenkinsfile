pipeline {
    agent {
        label 'parallel'
    }
    options {
        timeout(time: 120, unit: 'MINUTES')
        timestamps()
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
                    "K8s 1.6 multinode tests": {
                         sh 'cd ./tests/k8s && k8s_version="1.6.6-00" vagrant destroy -f || true'
                         sh 'k8s_version="1.6.6-00" ./tests/k8s/start.sh'
                    },
                    "K8s 1.7 multinode tests": {
                         sh 'cd ./tests/k8s && K8S=1.7 vagrant destroy -f || true'
                         sh 'k8s_version="1.7.4-00" ./tests/k8s/start.sh'
                    }
                )
            }
        }
    }
    post {
        always {
            sh './tests/copy_files || true'
            archiveArtifacts artifacts: "cilium-files-runtime-${JOB_BASE_NAME}-${BUILD_NUMBER}.tar.gz", allowEmptyArchive: true
            sh './tests/k8s/copy_files || true'
            archiveArtifacts artifacts: "cilium-files-k8s-${JOB_BASE_NAME}-${BUILD_NUMBER}.tar.gz", allowEmptyArchive: true
            sh 'rm -rf ${WORKSPACE}/cilium-files*${JOB_BASE_NAME}-${BUILD_NUMBER}* ${WORKSPACE}/tests/cilium-files ${WORKSPACE}/tests/k8s/tests/cilium-files'
            sh 'ls'
            sh 'vagrant destroy -f'
            sh 'cd ./tests/k8s && k8s_version="1.6.6-00" vagrant destroy -f'
            sh 'cd ./tests/k8s && k8s_version="1.7.4-00" vagrant destroy -f'
        }
    }
}
