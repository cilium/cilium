@Library('cilium') _

pipeline {
    agent none

    parameters {
        string(defaultValue: 'origin/master', name: 'GIT_BRANCH')
    }

    options {
        timeout(time: 540, unit: 'MINUTES')
        timestamps()
        ansiColor('xterm')
    }

    stages {
        // Abort build if not triggered against master branch
        //
        // `ginkgo-kubernetes-all.Jenkinsfile` is used in both
        // `cilium-master-K8s-all` and `Cilium-PR-Ginkgo-Tests-K8s`.
        // The former is triggered automatically daily, the latter is triggered
        // from PRs with `test-missed-k8s` but is now deprecated and superseded
        // by `test-older-k8s`, which directly runs other PR jobs.
        //
        // PRs for older branches (e.g. backports) still need `test-missed-k8s`,
        // hence we can't remove `Cilium-PR-Ginkgo-Tests-K8s` for now.
        // This guard's purpose is to prevent accidental triggering of master
        // jobs when using `test-missed-k8s` from PRs of recent branches.
        stage('Parameter check') {
            when {
                not { environment name: 'GIT_BRANCH', value: 'origin/master' }
            }
            steps {
                script {
                    currentBuild.result = 'ABORTED'
                }
                error("Aborting due to invalid target branch. Note: 'test-missed-k8s' is deprecated on new branches, please use 'test-older-k8s' instead. See documentation for details: https://docs.cilium.io/en/latest/contributing/testing/ci/#trigger-phrases")
            }
        }
        stage('Trigger parallel baremetal K8s builds') {
            parallel {
                stage('K8s-1.14-kernel-4.9') {
                    steps {
                        build(job: "Cilium-Master-K8s-1.14", parameters: [
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])  
                    }
                }

                stage('K8s-1.15-kernel-4.9') {
                    steps {
                        build(job: "Cilium-Master-K8s-1.15", parameters: [
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('K8s-1.16-kernel-4.9') {
                    steps {
                        build(job: "Cilium-Master-K8s-1.16", parameters: [
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('K8s-1.17-kernel-4.9') {
                    steps {
                        build(job: "Cilium-Master-K8s-1.17", parameters: [
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('K8s-1.18-kernel-4.9') {
                    steps {
                        build(job: "Cilium-Master-K8s-1.18", parameters: [
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])
                    }
                }

                stage('K8s-1.19-kernel-4.9') {
                    steps {
                        build(job: "Cilium-Master-K8s-1.19", parameters: [
                            string(name: 'GIT_BRANCH', value: "${GIT_BRANCH}")
                        ])
                    }
                }
            }
        }
    }
    post {
        success {
            Status("SUCCESS", "${env.JOB_NAME}")
        }
        failure {
            Status("FAILURE", "${env.JOB_NAME}")
        }
    }
}
