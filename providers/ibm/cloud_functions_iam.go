// Copyright 2019 The Terraformer Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ibm

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/GoogleCloudPlatform/terraformer/terraformutils"
	bluemix "github.com/IBM-Cloud/bluemix-go"

	ns "github.com/IBM-Cloud/bluemix-go/api/functions"
	"github.com/IBM-Cloud/bluemix-go/session"

	"github.com/apache/openwhisk-client-go/whisk"
)

// CloudFunctionIAMGenerator ..
type CloudFunctionIAMGenerator struct {
	IBMService
}

func (g CloudFunctionIAMGenerator) loadNamespaces(nsID, nsName string, resGrp string) terraformutils.Resource {
	var resources terraformutils.Resource
	resources = terraformutils.NewResource(
		nsID,
		nsID,
		"ibm_function_namespace",
		"ibm",
		map[string]string{
			"resource_group_id": resGrp,
		},
		[]string{},
		map[string]interface{}{})
	return resources
}

func (g CloudFunctionIAMGenerator) createResources() []terraformutils.Resource {
	var resources []terraformutils.Resource
	return resources
}

func (g CloudFunctionIAMGenerator) loadPackages(namespace, pkgName string, dependsOn []string) terraformutils.Resource {
	var resources terraformutils.Resource
	resources = terraformutils.NewResource(
		fmt.Sprintf("%s:%s", namespace, pkgName),
		pkgName,
		"ibm_function_package",
		"ibm",
		map[string]string{},
		[]string{},
		map[string]interface{}{
			"depends_on": dependsOn,
		})
	return resources
}

func (g CloudFunctionIAMGenerator) loadActions(namespace, actionID, actionName string, dependsOn []string) terraformutils.Resource {
	var resources terraformutils.Resource
	resources = terraformutils.NewResource(
		fmt.Sprintf("%s:%s", namespace, actionID),
		actionName,
		"ibm_function_action",
		"ibm",
		map[string]string{},
		[]string{},
		map[string]interface{}{
			"depends_on": dependsOn,
		})
	return resources
}

func (g CloudFunctionIAMGenerator) loadRules(namespace, ruleName string, dependsOn []string) terraformutils.Resource {
	var resources terraformutils.Resource
	resources = terraformutils.NewResource(
		fmt.Sprintf("%s:%s", namespace, ruleName),
		ruleName,
		"ibm_function_rule",
		"ibm",
		map[string]string{},
		[]string{},
		map[string]interface{}{
			"depends_on": dependsOn,
		})
	return resources
}

func (g CloudFunctionIAMGenerator) loadTriggers(namespace, triggerName string, dependsOn []string) terraformutils.Resource {
	var resources terraformutils.Resource
	resources = terraformutils.NewResource(
		fmt.Sprintf("%s:%s", namespace, triggerName),
		triggerName,
		"ibm_function_trigger",
		"ibm",
		map[string]string{},
		[]string{},
		map[string]interface{}{
			"depends_on": dependsOn,
		})
	return resources
}

/*
 *
 * Configure a HTTP client using the OpenWhisk properties (i.e. host, auth, iamtoken)
 * Only cf-based namespaces needs auth key value.
 * iam-based namespace don't have an auth key and needs only iam token for authorization.
 *
 */
func setupOpenWhiskClientConfigIAM(response ns.NamespaceResponse, c *bluemix.Config) (*whisk.Client, error) {
	if c.UAAAccessToken == "" && c.UAARefreshToken == "" {
		return nil, fmt.Errorf("Couldn't retrieve auth key for IBM Cloud Function")
	}

	u, _ := url.Parse(fmt.Sprintf("https://%s.functions.cloud.ibm.com/api", "us-south"))
	wskClient, _ := whisk.NewClient(http.DefaultClient, &whisk.Config{
		Host:    u.Host,
		Version: "v1",
	})

	if os.Getenv("TF_LOG") != "" {
		whisk.SetDebug(true)
	}

	// Configure whisk properties to handle iam-based/iam-migrated  namespaces.
	if response.IsIamEnabled() {
		additionalHeaders := make(http.Header)
		additionalHeaders.Add("Authorization", c.IAMAccessToken)
		additionalHeaders.Add("X-Namespace-Id", response.GetID())

		wskClient.Config.Namespace = response.GetID()
		wskClient.Config.AdditionalHeaders = additionalHeaders
		return wskClient, nil
	}

	return nil, fmt.Errorf("Failed to create whisk config object for IAM based namespace '%v'", response.GetName())
}

// InitResources ..
func (g *CloudFunctionIAMGenerator) InitResources() error {
	bmxConfig := &bluemix.Config{
		BluemixAPIKey: os.Getenv("IC_API_KEY"),
	}

	sess, err := session.New(bmxConfig)
	if err != nil {
		return err
	}

	err = authenticateAPIKey(sess)
	if err != nil {
		return err
	}

	err = authenticateCF(sess)
	if err != nil {
		return err
	}

	nsClient, err := ns.New(sess)
	if err != nil {
		return err
	}

	nsList, err := nsClient.Namespaces().GetNamespaces()
	if err != nil {
		return nil
	}

	for _, n := range nsList.Namespaces {
		var dependsOn []string
		dependsOn = append(dependsOn,
			"ibm_function_namespace."+terraformutils.TfSanitize(n.GetID()))

		//Namespace
		if n.IsCf() {
			continue
		}
		//Build whisk object
		wskClient, err := setupOpenWhiskClientConfigIAM(n, sess.Config)
		if err != nil {
			return err
		}

		//Package
		packageService := wskClient.Packages
		pkgOptions := &whisk.PackageListOptions{
			Limit: 100,
			Skip:  0,
		}
		pkgs, _, err := packageService.List(pkgOptions)
		if err != nil {
			return fmt.Errorf("Error retrieving IBM Cloud Function package: %s", err)
		}
		for _, p := range pkgs {
			g.Resources = append(g.Resources, g.loadPackages(n.GetName(), p.GetName(), dependsOn))
		}

		//Action
		actionService := wskClient.Actions
		actionOptions := &whisk.ActionListOptions{
			Limit: 100,
			Skip:  0,
		}
		actions, _, err := actionService.List("", actionOptions)
		if err != nil {
			return fmt.Errorf("Error retrieving IBM Cloud Function action: %s", err)
		}

		for _, a := range actions {
			actionID := ""
			parts := strings.Split(a.Namespace, "/")
			if len(parts) == 2 {
				actionID = fmt.Sprintf("%s/%s", parts[1], a.Name)
			} else {
				actionID = a.Name
			}
			g.Resources = append(g.Resources, g.loadActions(n.GetName(), actionID, a.Name, dependsOn))
		}

		//Rule
		ruleService := wskClient.Rules
		ruleOptions := &whisk.RuleListOptions{
			Limit: 100,
			Skip:  0,
		}
		rules, _, err := ruleService.List(ruleOptions)
		if err != nil {
			return fmt.Errorf("Error retrieving IBM Cloud Function rule: %s", err)
		}

		for _, r := range rules {
			g.Resources = append(g.Resources, g.loadRules(n.GetName(), r.Name, dependsOn))
		}

		//Triggers
		triggerService := wskClient.Triggers
		triggerOptions := &whisk.TriggerListOptions{
			Limit: 100,
			Skip:  0,
		}
		triggers, _, err := triggerService.List(triggerOptions)
		if err != nil {
			return fmt.Errorf("Error retrieving IBM Cloud Function trigger: %s", err)
		}

		for _, t := range triggers {
			g.Resources = append(g.Resources, g.loadTriggers(n.GetName(), t.Name, dependsOn))
		}
	}

	return nil
}
