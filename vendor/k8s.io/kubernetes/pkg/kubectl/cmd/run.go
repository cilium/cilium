/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"fmt"
	"io"

	"github.com/docker/distribution/reference"
	"github.com/spf13/cobra"

	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	batchv2alpha1 "k8s.io/api/batch/v2alpha1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/kubernetes/pkg/api"
	coreclient "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/core/internalversion"
	conditions "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/kubectl"
	"k8s.io/kubernetes/pkg/kubectl/cmd/templates"
	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/kubectl/resource"
	"k8s.io/kubernetes/pkg/kubectl/util/i18n"
	"k8s.io/kubernetes/pkg/util/interrupt"
	uexec "k8s.io/utils/exec"
)

var (
	runLong = templates.LongDesc(i18n.T(`
		Create and run a particular image, possibly replicated.

		Creates a deployment or job to manage the created container(s).`))

	runExample = templates.Examples(i18n.T(`
		# Start a single instance of nginx.
		kubectl run nginx --image=nginx

		# Start a single instance of hazelcast and let the container expose port 5701 .
		kubectl run hazelcast --image=hazelcast --port=5701

		# Start a single instance of hazelcast and set environment variables "DNS_DOMAIN=cluster" and "POD_NAMESPACE=default" in the container.
		kubectl run hazelcast --image=hazelcast --env="DNS_DOMAIN=cluster" --env="POD_NAMESPACE=default"

		# Start a single instance of hazelcast and set labels "app=hazelcast" and "env=prod" in the container.
		kubectl run hazelcast --image=nginx --labels="app=hazelcast,env=prod"

		# Start a replicated instance of nginx.
		kubectl run nginx --image=nginx --replicas=5

		# Dry run. Print the corresponding API objects without creating them.
		kubectl run nginx --image=nginx --dry-run

		# Start a single instance of nginx, but overload the spec of the deployment with a partial set of values parsed from JSON.
		kubectl run nginx --image=nginx --overrides='{ "apiVersion": "v1", "spec": { ... } }'

		# Start a pod of busybox and keep it in the foreground, don't restart it if it exits.
		kubectl run -i -t busybox --image=busybox --restart=Never

		# Start the nginx container using the default command, but use custom arguments (arg1 .. argN) for that command.
		kubectl run nginx --image=nginx -- <arg1> <arg2> ... <argN>

		# Start the nginx container using a different command and custom arguments.
		kubectl run nginx --image=nginx --command -- <cmd> <arg1> ... <argN>

		# Start the perl container to compute π to 2000 places and print it out.
		kubectl run pi --image=perl --restart=OnFailure -- perl -Mbignum=bpi -wle 'print bpi(2000)'

		# Start the cron job to compute π to 2000 places and print it out every 5 minutes.
		kubectl run pi --schedule="0/5 * * * ?" --image=perl --restart=OnFailure -- perl -Mbignum=bpi -wle 'print bpi(2000)'`))
)

type RunObject struct {
	Object  runtime.Object
	Kind    string
	Mapper  meta.RESTMapper
	Mapping *meta.RESTMapping
}

func NewCmdRun(f cmdutil.Factory, cmdIn io.Reader, cmdOut, cmdErr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "run NAME --image=image [--env=\"key=value\"] [--port=port] [--replicas=replicas] [--dry-run=bool] [--overrides=inline-json] [--command] -- [COMMAND] [args...]",
		Short:   i18n.T("Run a particular image on the cluster"),
		Long:    runLong,
		Example: runExample,
		Run: func(cmd *cobra.Command, args []string) {
			argsLenAtDash := cmd.ArgsLenAtDash()
			err := RunRun(f, cmdIn, cmdOut, cmdErr, cmd, args, argsLenAtDash)
			cmdutil.CheckErr(err)
		},
	}
	cmdutil.AddPrinterFlags(cmd)
	addRunFlags(cmd)
	cmdutil.AddApplyAnnotationFlags(cmd)
	cmdutil.AddRecordFlag(cmd)
	cmdutil.AddInclude3rdPartyFlags(cmd)
	cmdutil.AddPodRunningTimeoutFlag(cmd, defaultPodAttachTimeout)
	return cmd
}

func addRunFlags(cmd *cobra.Command) {
	cmdutil.AddDryRunFlag(cmd)
	cmd.Flags().String("generator", "", i18n.T("The name of the API generator to use, see http://kubernetes.io/docs/user-guide/kubectl-conventions/#generators for a list."))
	cmd.Flags().String("image", "", i18n.T("The image for the container to run."))
	cmd.MarkFlagRequired("image")
	cmd.Flags().String("image-pull-policy", "", i18n.T("The image pull policy for the container. If left empty, this value will not be specified by the client and defaulted by the server"))
	cmd.Flags().IntP("replicas", "r", 1, "Number of replicas to create for this container. Default is 1.")
	cmd.Flags().Bool("rm", false, "If true, delete resources created in this command for attached containers.")
	cmd.Flags().String("overrides", "", i18n.T("An inline JSON override for the generated object. If this is non-empty, it is used to override the generated object. Requires that the object supply a valid apiVersion field."))
	cmd.Flags().StringArray("env", []string{}, "Environment variables to set in the container")
	cmd.Flags().String("serviceaccount", "", "Service account to set in the pod spec")
	cmd.Flags().String("port", "", i18n.T("The port that this container exposes.  If --expose is true, this is also the port used by the service that is created."))
	cmd.Flags().Int("hostport", -1, "The host port mapping for the container port. To demonstrate a single-machine container.")
	cmd.Flags().StringP("labels", "l", "", "Comma separated labels to apply to the pod(s). Will override previous values.")
	cmd.Flags().BoolP("stdin", "i", false, "Keep stdin open on the container(s) in the pod, even if nothing is attached.")
	cmd.Flags().BoolP("tty", "t", false, "Allocated a TTY for each container in the pod.")
	cmd.Flags().Bool("attach", false, "If true, wait for the Pod to start running, and then attach to the Pod as if 'kubectl attach ...' were called.  Default false, unless '-i/--stdin' is set, in which case the default is true. With '--restart=Never' the exit code of the container process is returned.")
	cmd.Flags().Bool("leave-stdin-open", false, "If the pod is started in interactive mode or with stdin, leave stdin open after the first attach completes. By default, stdin will be closed after the first attach completes.")
	cmd.Flags().String("restart", "Always", i18n.T("The restart policy for this Pod.  Legal values [Always, OnFailure, Never].  If set to 'Always' a deployment is created, if set to 'OnFailure' a job is created, if set to 'Never', a regular pod is created. For the latter two --replicas must be 1.  Default 'Always', for CronJobs `Never`."))
	cmd.Flags().Bool("command", false, "If true and extra arguments are present, use them as the 'command' field in the container, rather than the 'args' field which is the default.")
	cmd.Flags().String("requests", "", i18n.T("The resource requirement requests for this container.  For example, 'cpu=100m,memory=256Mi'.  Note that server side components may assign requests depending on the server configuration, such as limit ranges."))
	cmd.Flags().String("limits", "", i18n.T("The resource requirement limits for this container.  For example, 'cpu=200m,memory=512Mi'.  Note that server side components may assign limits depending on the server configuration, such as limit ranges."))
	cmd.Flags().Bool("expose", false, "If true, a public, external service is created for the container(s) which are run")
	cmd.Flags().String("service-generator", "service/v2", i18n.T("The name of the generator to use for creating a service.  Only used if --expose is true"))
	cmd.Flags().String("service-overrides", "", i18n.T("An inline JSON override for the generated service object. If this is non-empty, it is used to override the generated object. Requires that the object supply a valid apiVersion field.  Only used if --expose is true."))
	cmd.Flags().Bool("quiet", false, "If true, suppress prompt messages.")
	cmd.Flags().String("schedule", "", i18n.T("A schedule in the Cron format the job should be run with."))
}

func RunRun(f cmdutil.Factory, cmdIn io.Reader, cmdOut, cmdErr io.Writer, cmd *cobra.Command, args []string, argsLenAtDash int) error {
	// Let kubectl run follow rules for `--`, see #13004 issue
	if len(args) == 0 || argsLenAtDash == 0 {
		return cmdutil.UsageErrorf(cmd, "NAME is required for run")
	}

	timeout, err := cmdutil.GetPodRunningTimeoutFlag(cmd)
	if err != nil {
		return cmdutil.UsageErrorf(cmd, "%v", err)
	}

	// validate image name
	imageName := cmdutil.GetFlagString(cmd, "image")
	if imageName == "" {
		return fmt.Errorf("--image is required")
	}
	validImageRef := reference.ReferenceRegexp.MatchString(imageName)
	if !validImageRef {
		return fmt.Errorf("Invalid image name %q: %v", imageName, reference.ErrReferenceInvalidFormat)
	}

	interactive := cmdutil.GetFlagBool(cmd, "stdin")
	tty := cmdutil.GetFlagBool(cmd, "tty")
	if tty && !interactive {
		return cmdutil.UsageErrorf(cmd, "-i/--stdin is required for containers with -t/--tty=true")
	}
	replicas := cmdutil.GetFlagInt(cmd, "replicas")
	if interactive && replicas != 1 {
		return cmdutil.UsageErrorf(cmd, "-i/--stdin requires that replicas is 1, found %d", replicas)
	}
	if cmdutil.GetFlagBool(cmd, "expose") && len(cmdutil.GetFlagString(cmd, "port")) == 0 {
		return cmdutil.UsageErrorf(cmd, "--port must be set when exposing a service")
	}

	namespace, _, err := f.DefaultNamespace()
	if err != nil {
		return err
	}
	restartPolicy, err := getRestartPolicy(cmd, interactive)
	if err != nil {
		return err
	}
	if restartPolicy != api.RestartPolicyAlways && replicas != 1 {
		return cmdutil.UsageErrorf(cmd, "--restart=%s requires that --replicas=1, found %d", restartPolicy, replicas)
	}

	attachFlag := cmd.Flags().Lookup("attach")
	attach := cmdutil.GetFlagBool(cmd, "attach")

	if !attachFlag.Changed && interactive {
		attach = true
	}

	remove := cmdutil.GetFlagBool(cmd, "rm")
	if !attach && remove {
		return cmdutil.UsageErrorf(cmd, "--rm should only be used for attached containers")
	}

	if attach && cmdutil.GetDryRunFlag(cmd) {
		return cmdutil.UsageErrorf(cmd, "--dry-run can't be used with attached containers options (--attach, --stdin, or --tty)")
	}

	if err := verifyImagePullPolicy(cmd); err != nil {
		return err
	}

	clientset, err := f.ClientSet()
	if err != nil {
		return err
	}
	resourcesList, err := clientset.Discovery().ServerResources()
	// ServerResources ignores errors for old servers do not expose discovery
	if err != nil {
		return fmt.Errorf("failed to discover supported resources: %v", err)
	}

	generatorName := cmdutil.GetFlagString(cmd, "generator")
	schedule := cmdutil.GetFlagString(cmd, "schedule")
	if len(schedule) != 0 && len(generatorName) == 0 {
		if contains(resourcesList, batchv1beta1.SchemeGroupVersion.WithResource("cronjobs")) {
			generatorName = cmdutil.CronJobV1Beta1GeneratorName
		} else {
			generatorName = cmdutil.CronJobV2Alpha1GeneratorName
		}
	}
	if len(generatorName) == 0 {
		switch restartPolicy {
		case api.RestartPolicyAlways:
			// TODO: we need to deprecate this along with extensions/v1beta1.Deployments
			// in favor of the new generator for apps/v1beta1.Deployments
			if contains(resourcesList, extensionsv1beta1.SchemeGroupVersion.WithResource("deployments")) {
				generatorName = cmdutil.DeploymentV1Beta1GeneratorName
			} else {
				generatorName = cmdutil.RunV1GeneratorName
			}
		case api.RestartPolicyOnFailure:
			if contains(resourcesList, batchv1.SchemeGroupVersion.WithResource("jobs")) {
				generatorName = cmdutil.JobV1GeneratorName
			} else {
				generatorName = cmdutil.RunPodV1GeneratorName
			}
		case api.RestartPolicyNever:
			generatorName = cmdutil.RunPodV1GeneratorName
		}
	}

	// TODO: this should be removed alongside with extensions/v1beta1 depployments generator
	generatorName = fallbackGeneratorNameIfNecessary(generatorName, resourcesList, cmdErr)

	if generatorName == cmdutil.CronJobV2Alpha1GeneratorName &&
		!contains(resourcesList, batchv2alpha1.SchemeGroupVersion.WithResource("cronjobs")) {
		return fmt.Errorf("CronJob generator specified, but batch/v2alpha1.CronJobs are not available")
	}

	generators := f.Generators("run")
	generator, found := generators[generatorName]
	if !found {
		return cmdutil.UsageErrorf(cmd, "generator %q not found", generatorName)
	}
	names := generator.ParamNames()
	params := kubectl.MakeParams(cmd, names)
	params["name"] = args[0]
	if len(args) > 1 {
		params["args"] = args[1:]
	}

	params["env"] = cmdutil.GetFlagStringArray(cmd, "env")

	var runObjectMap = map[string]*RunObject{}
	runObject, err := createGeneratedObject(f, cmd, generator, names, params, cmdutil.GetFlagString(cmd, "overrides"), namespace)
	if err != nil {
		return err
	}
	runObjectMap[generatorName] = runObject

	if cmdutil.GetFlagBool(cmd, "expose") {
		serviceGenerator := cmdutil.GetFlagString(cmd, "service-generator")
		if len(serviceGenerator) == 0 {
			return cmdutil.UsageErrorf(cmd, "No service generator specified")
		}
		serviceRunObject, err := generateService(f, cmd, args, serviceGenerator, params, namespace, cmdOut)
		if err != nil {
			return err
		}
		runObjectMap[generatorName] = serviceRunObject
	}

	if attach {
		quiet := cmdutil.GetFlagBool(cmd, "quiet")
		opts := &AttachOptions{
			StreamOptions: StreamOptions{
				In:    cmdIn,
				Out:   cmdOut,
				Err:   cmdErr,
				Stdin: interactive,
				TTY:   tty,
				Quiet: quiet,
			},
			GetPodTimeout: timeout,
			CommandName:   cmd.Parent().CommandPath() + " attach",

			Attach: &DefaultRemoteAttach{},
		}
		config, err := f.ClientConfig()
		if err != nil {
			return err
		}
		opts.Config = config

		clientset, err := f.ClientSet()
		if err != nil {
			return err
		}
		opts.PodClient = clientset.Core()

		attachablePod, err := f.AttachablePodForObject(runObject.Object, opts.GetPodTimeout)
		if err != nil {
			return err
		}
		err = handleAttachPod(f, clientset.Core(), attachablePod.Namespace, attachablePod.Name, opts)
		if err != nil {
			return err
		}

		var pod *api.Pod
		leaveStdinOpen := cmdutil.GetFlagBool(cmd, "leave-stdin-open")
		waitForExitCode := !leaveStdinOpen && restartPolicy == api.RestartPolicyNever
		if waitForExitCode {
			pod, err = waitForPodTerminated(clientset.Core(), attachablePod.Namespace, attachablePod.Name)
			if err != nil {
				return err
			}
		}

		if remove {
			for _, obj := range runObjectMap {
				namespace, err = obj.Mapping.MetadataAccessor.Namespace(obj.Object)
				if err != nil {
					return err
				}
				var name string
				name, err = obj.Mapping.MetadataAccessor.Name(obj.Object)
				if err != nil {
					return err
				}
				r := f.NewBuilder(true).
					ContinueOnError().
					NamespaceParam(namespace).DefaultNamespace().
					ResourceNames(obj.Mapping.Resource, name).
					Flatten().
					Do()
				// Note: we pass in "true" for the "quiet" parameter because
				// ReadResult will only print one thing based on the "quiet"
				// flag, and that's the "pod xxx deleted" message. If they
				// asked for us to remove the pod (via --rm) then telling them
				// its been deleted is unnecessary since that's what they asked
				// for. We should only print something if the "rm" fails.
				err = ReapResult(r, f, cmdOut, true, true, 0, -1, false, false, obj.Mapper, true)
				if err != nil {
					return err
				}
			}
		}

		// after removal is done, return successfully if we are not interested in the exit code
		if !waitForExitCode {
			return nil
		}

		switch pod.Status.Phase {
		case api.PodSucceeded:
			return nil
		case api.PodFailed:
			unknownRcErr := fmt.Errorf("pod %s/%s failed with unknown exit code", pod.Namespace, pod.Name)
			if len(pod.Status.ContainerStatuses) == 0 || pod.Status.ContainerStatuses[0].State.Terminated == nil {
				return unknownRcErr
			}
			// assume here that we have at most one status because kubectl-run only creates one container per pod
			rc := pod.Status.ContainerStatuses[0].State.Terminated.ExitCode
			if rc == 0 {
				return unknownRcErr
			}
			return uexec.CodeExitError{
				Err:  fmt.Errorf("pod %s/%s terminated (%s)\n%s", pod.Namespace, pod.Name, pod.Status.ContainerStatuses[0].State.Terminated.Reason, pod.Status.ContainerStatuses[0].State.Terminated.Message),
				Code: int(rc),
			}
		default:
			return fmt.Errorf("pod %s/%s left in phase %s", pod.Namespace, pod.Name, pod.Status.Phase)
		}

	}

	outputFormat := cmdutil.GetFlagString(cmd, "output")
	if outputFormat != "" || cmdutil.GetDryRunFlag(cmd) {
		return f.PrintObject(cmd, false, runObject.Mapper, runObject.Object, cmdOut)
	}
	cmdutil.PrintSuccess(runObject.Mapper, false, cmdOut, runObject.Mapping.Resource, args[0], cmdutil.GetDryRunFlag(cmd), "created")
	return nil
}

// TODO turn this into reusable method checking available resources
func contains(resourcesList []*metav1.APIResourceList, resource schema.GroupVersionResource) bool {
	resources := discovery.FilteredBy(discovery.ResourcePredicateFunc(func(gv string, r *metav1.APIResource) bool {
		return resource.GroupVersion().String() == gv && resource.Resource == r.Name
	}), resourcesList)
	return len(resources) != 0
}

// waitForPod watches the given pod until the exitCondition is true
func waitForPod(podClient coreclient.PodsGetter, ns, name string, exitCondition watch.ConditionFunc) (*api.Pod, error) {
	w, err := podClient.Pods(ns).Watch(metav1.SingleObject(metav1.ObjectMeta{Name: name}))
	if err != nil {
		return nil, err
	}

	intr := interrupt.New(nil, w.Stop)
	var result *api.Pod
	err = intr.Run(func() error {
		ev, err := watch.Until(0, w, func(ev watch.Event) (bool, error) {
			return exitCondition(ev)
		})
		if ev != nil {
			result = ev.Object.(*api.Pod)
		}
		return err
	})
	return result, err
}

func waitForPodRunning(podClient coreclient.PodsGetter, ns, name string) (*api.Pod, error) {
	pod, err := waitForPod(podClient, ns, name, conditions.PodRunningAndReady)

	// fix generic not found error with empty name in PodRunningAndReady
	if err != nil && errors.IsNotFound(err) {
		return nil, errors.NewNotFound(api.Resource("pods"), name)
	}

	return pod, err
}

func waitForPodTerminated(podClient coreclient.PodsGetter, ns, name string) (*api.Pod, error) {
	pod, err := waitForPod(podClient, ns, name, conditions.PodCompleted)

	// fix generic not found error with empty name in PodCompleted
	if err != nil && errors.IsNotFound(err) {
		return nil, errors.NewNotFound(api.Resource("pods"), name)
	}

	return pod, err
}

func handleAttachPod(f cmdutil.Factory, podClient coreclient.PodsGetter, ns, name string, opts *AttachOptions) error {
	pod, err := waitForPodRunning(podClient, ns, name)
	if err != nil && err != conditions.ErrPodCompleted {
		return err
	}

	if pod.Status.Phase == api.PodSucceeded || pod.Status.Phase == api.PodFailed {
		return logOpts(f, pod, opts)
	}

	opts.PodClient = podClient
	opts.PodName = name
	opts.Namespace = ns

	// TODO: opts.Run sets opts.Err to nil, we need to find a better way
	stderr := opts.Err
	if err := opts.Run(); err != nil {
		fmt.Fprintf(stderr, "Error attaching, falling back to logs: %v\n", err)
		return logOpts(f, pod, opts)
	}
	return nil
}

// logOpts logs output from opts to the pods log.
func logOpts(f cmdutil.Factory, pod *api.Pod, opts *AttachOptions) error {
	ctrName, err := opts.GetContainerName(pod)
	if err != nil {
		return err
	}

	req, err := f.LogsForObject(pod, &api.PodLogOptions{Container: ctrName}, opts.GetPodTimeout)
	if err != nil {
		return err
	}

	readCloser, err := req.Stream()
	if err != nil {
		return err
	}
	defer readCloser.Close()

	_, err = io.Copy(opts.Out, readCloser)
	if err != nil {
		return err
	}
	return nil
}

func getRestartPolicy(cmd *cobra.Command, interactive bool) (api.RestartPolicy, error) {
	restart := cmdutil.GetFlagString(cmd, "restart")
	if len(restart) == 0 {
		if interactive {
			return api.RestartPolicyOnFailure, nil
		} else {
			return api.RestartPolicyAlways, nil
		}
	}
	switch api.RestartPolicy(restart) {
	case api.RestartPolicyAlways:
		return api.RestartPolicyAlways, nil
	case api.RestartPolicyOnFailure:
		return api.RestartPolicyOnFailure, nil
	case api.RestartPolicyNever:
		return api.RestartPolicyNever, nil
	}
	return "", cmdutil.UsageErrorf(cmd, "invalid restart policy: %s")
}

func verifyImagePullPolicy(cmd *cobra.Command) error {
	pullPolicy := cmdutil.GetFlagString(cmd, "image-pull-policy")
	switch api.PullPolicy(pullPolicy) {
	case api.PullAlways, api.PullIfNotPresent, api.PullNever:
		return nil
	case "":
		return nil
	}
	return cmdutil.UsageErrorf(cmd, "invalid image pull policy: %s", pullPolicy)
}

func generateService(f cmdutil.Factory, cmd *cobra.Command, args []string, serviceGenerator string, paramsIn map[string]interface{}, namespace string, out io.Writer) (*RunObject, error) {
	generators := f.Generators("expose")
	generator, found := generators[serviceGenerator]
	if !found {
		return nil, fmt.Errorf("missing service generator: %s", serviceGenerator)
	}
	names := generator.ParamNames()

	params := map[string]interface{}{}
	for key, value := range paramsIn {
		_, isString := value.(string)
		if isString {
			params[key] = value
		}
	}

	name, found := params["name"]
	if !found || len(name.(string)) == 0 {
		return nil, fmt.Errorf("name is a required parameter")
	}
	selector, found := params["labels"]
	if !found || len(selector.(string)) == 0 {
		selector = fmt.Sprintf("run=%s", name.(string))
	}
	params["selector"] = selector

	if defaultName, found := params["default-name"]; !found || len(defaultName.(string)) == 0 {
		params["default-name"] = name
	}

	runObject, err := createGeneratedObject(f, cmd, generator, names, params, cmdutil.GetFlagString(cmd, "service-overrides"), namespace)
	if err != nil {
		return nil, err
	}

	if cmdutil.GetFlagString(cmd, "output") != "" || cmdutil.GetDryRunFlag(cmd) {
		err := f.PrintObject(cmd, false, runObject.Mapper, runObject.Object, out)
		if err != nil {
			return nil, err
		}
		if cmdutil.GetFlagString(cmd, "output") == "yaml" {
			fmt.Fprintln(out, "---")
		}
		return runObject, nil
	}
	cmdutil.PrintSuccess(runObject.Mapper, false, out, runObject.Mapping.Resource, args[0], cmdutil.GetDryRunFlag(cmd), "created")

	return runObject, nil
}

func createGeneratedObject(f cmdutil.Factory, cmd *cobra.Command, generator kubectl.Generator, names []kubectl.GeneratorParam, params map[string]interface{}, overrides, namespace string) (*RunObject, error) {
	err := kubectl.ValidateParams(names, params)
	if err != nil {
		return nil, err
	}

	// TODO: Validate flag usage against selected generator. More tricky since --expose was added.
	obj, err := generator.Generate(params)
	if err != nil {
		return nil, err
	}

	mapper, typer := f.Object()
	groupVersionKinds, _, err := typer.ObjectKinds(obj)
	if err != nil {
		return nil, err
	}
	groupVersionKind := groupVersionKinds[0]

	if len(overrides) > 0 {
		codec := runtime.NewCodec(f.JSONEncoder(), f.Decoder(true))
		obj, err = cmdutil.Merge(codec, obj, overrides)
		if err != nil {
			return nil, err
		}
	}

	mapping, err := mapper.RESTMapping(groupVersionKind.GroupKind(), groupVersionKind.Version)
	if err != nil {
		return nil, err
	}
	client, err := f.ClientForMapping(mapping)
	if err != nil {
		return nil, err
	}

	annotations, err := mapping.MetadataAccessor.Annotations(obj)
	if err != nil {
		return nil, err
	}
	if cmdutil.GetRecordFlag(cmd) || len(annotations[kubectl.ChangeCauseAnnotation]) > 0 {
		if err := cmdutil.RecordChangeCause(obj, f.Command(cmd, false)); err != nil {
			return nil, err
		}
	}
	if !cmdutil.GetDryRunFlag(cmd) {
		resourceMapper := &resource.Mapper{
			ObjectTyper:  typer,
			RESTMapper:   mapper,
			ClientMapper: resource.ClientMapperFunc(f.ClientForMapping),
			Decoder:      f.Decoder(true),
		}
		info, err := resourceMapper.InfoForObject(obj, nil)
		if err != nil {
			return nil, err
		}

		if err := kubectl.CreateOrUpdateAnnotation(cmdutil.GetFlagBool(cmd, cmdutil.ApplyAnnotationsFlag), info, f.JSONEncoder()); err != nil {
			return nil, err
		}

		obj, err = resource.NewHelper(client, mapping).Create(namespace, false, info.Object)
		if err != nil {
			return nil, err
		}
	}
	return &RunObject{
		Object:  obj,
		Kind:    groupVersionKind.Kind,
		Mapper:  mapper,
		Mapping: mapping,
	}, nil
}
