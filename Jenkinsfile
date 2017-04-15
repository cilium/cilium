pipeline {
	agent {
		label 'vagrant'
	}
	options {
		timeout(time: 30, unit: 'MINUTES')
	}
	stages {
		stage('Build') {
			environment {
				MEMORY = '4096'
				RUN_TEST_SUITE = '1'
				K8S = '1'
				IPV4 = '1'
			}
			steps {
				sh './contrib/vagrant/start.sh'
			}
		}
	}
	post {
		always {
			sh 'vagrant destroy -f'
		}
	}
}
