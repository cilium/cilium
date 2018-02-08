pipeline {
    agent {
        label 'vagrant'
    }
    options {
        timeout(time: 140, unit: 'MINUTES')
        timestamps()
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
            options {
                timeout(time: 120, unit: 'MINUTES')
            }
            steps {
                parallel(
                    "Print Environment": { sh 'env' },
                    "Runtime Tests": {
                         sh 'PROVISION=1 ./contrib/vagrant/start.sh'
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
            sh 'vagrant destroy -f || true'
        }
    }
}
