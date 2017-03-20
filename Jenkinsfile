pipeline {
    agent {
        label 'vagrant'
    }
    stages {
        stage('Build') {
            environment {
                MEMORY = '4096'
                RUN_TEST_SUITE = '1'
            }
            steps {
                sh './contrib/vagrant/start.sh'
            }
        }
    }
    post {
        always {
            sh 'vagrant ssh -c "sudo cat /var/log/upstart/cilium-consul.log" > cilium-consul.log || true'
            sh 'vagrant ssh -c "sudo cat /var/log/upstart/cilium-docker.log" > cilium-docker.log || true'
            sh 'vagrant ssh -c "sudo cat /var/log/upstart/cilium-etcd.log" > cilium-etcd.log || true'
            sh 'vagrant ssh -c "sudo cat /var/log/upstart/cilium.log" > cilium.log || true'
            archiveArtifacts artifacts: 'cilium*.log', fingerprint: true
            sh 'vagrant destroy -f'
        }
    }
}
