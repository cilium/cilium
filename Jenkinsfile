pipeline {
    agent {
        label 'vagrant'
    }
    options {
        timeout(time: 40, unit: 'MINUTES')
    }
    stages {
        stage ('Tests') {
                environment {
                    MEMORY = '4096'
                    RUN_TEST_SUITE = '1'
		}
		steps {
                    parallel(
                        "Runtime Tests": { sh './contrib/vagrant/start.sh' }, 
                        "K8s Tests": { sh './tests/k8s/start' },
                        "K8s multi node Tests": { sh './tests/k8s/multi-node/start.sh' }
                    )
	        }
        }
    }
    post {
        always {
            sh './tests/copy_files'
            archiveArtifacts "cilium-files.tar.gz"
            sh 'vagrant destroy -f'
            sh 'cd ./tests/k8s && vagrant destroy -f'
            sh 'cd ./tests/k8s/multi-node && vagrant destroy -f'
        }
    }
}
