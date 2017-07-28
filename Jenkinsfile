pipeline {
    agent {
        label 'vagrant'
    }
    options {
        timeout(time: 60, unit: 'MINUTES')
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
                    "Runtime Tests": { sh './contrib/vagrant/start.sh' },
                    "K8s multi node Tests": { sh './tests/k8s/start.sh' }
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
            sh 'vagrant destroy -f'
            sh 'cd ./tests/k8s && vagrant destroy -f'
        }
    }
}
