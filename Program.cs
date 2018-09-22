using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Amazon;
using Amazon.GuardDuty;
using Amazon.GuardDuty.Model;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using CommandLine;
using Newtonsoft.Json;

namespace guardduty_stix
{
    class Program
    {
        public class Options
        {
            [Option('p', "profile", Required = false, HelpText = "Connect to the AWS account with the credential stored in a named profile")]
            public string Profile { get; set; }

            [Option('k', "key", Required = false, HelpText = "Instead of a profile, use the specified AWS access key")]
            public string AccessKeyId { get; set; }

            [Option('s', "secret", Required = false, HelpText = "Instead of a profile, use the specified AWS access secret")]
            public string AccessKeySecret { get; set; }

            [Option('r', "region", Required = false, HelpText = "Instead of a profile, use the specified AWS region", Default = "us-east-1")]
            public string Region { get; set; }

            [Option('v', "verbose", Required = false, HelpText = "Set output to verbose messages.")]
            public bool Verbose { get; set; }
        }

        private static string[] titleBanner = new string[] {
            @"   ______                     ______        __       ",
            @"  / ____/_  ______ __________/ / __ \__  __/ /___  __",
            @" / / __/ / / / __ `/ ___/ __  / / / / / / / __/ / / /",
            @"/ /_/ / /_/ / /_/ / /  / /_/ / /_/ / /_/ / /_/ /_/ / ",
            @"\____/\________________\____/_____/\________/\__, /  ",
            @"      / ___/_  __/  _/ |/ /   |__ \  / __ \ /____/   ",
            @"      \__ \ / /  / / |   /    __/ / / / / /          ",
            @"     ___/ // / _/ / /   |    / __/_/ /_/ /           ",
            @"    /____//_/ /___//_/|_|   /____(_)____/            ",
            @"",
            @" A program to turn GuardDuty findings from the AWS API",
            @" into compliant STIX 2.0",
            @"",
            @" Copyright Sean McElroy 2018.  All rights reserved.  ",
            @" Released under the terms of the MIT License.        ",
            @""
        };

        private static string[] helpScreen = new string[] {
            @"This program converts AWS GuardDuty findings into STIX 2.0",
            @"",
            @" Command line arguments: ",
            @"  --profile=PROFILE_NAME      Connect to the AWS account with the credential stored in a named profile",
            @"  --key=ACCESS_KEY_ID         Instead of a profile, use the specified AWS access key",
            @"  --secret=ACCESS_KEY_SECRET  Instead of a profile, use the specified AWS access secret",
            @"",
        };

        static int Main(string[] args)
        {
            foreach (var line in titleBanner)
                Console.WriteLine(line);

            if (args == null || args.Length == 0)
            {
                // Help screen
                foreach (var line in helpScreen)
                    Console.WriteLine(line);
                System.Environment.Exit(-1);
            }

            Options options = null;
            Parser.Default.ParseArguments<Options>(args)
            .WithParsed(o => options = o)
            .WithNotParsed(errors =>
            {
                foreach (var error in errors)
                    Console.WriteLine(error);
                System.Environment.Exit(-2);
            });

            // Setup AWS credentials
            var chain = new CredentialProfileStoreChain();

            AWSCredentials awsCredentials;
            RegionEndpoint awsRegion;

            if (!string.IsNullOrWhiteSpace(options.Profile))
            {
                if (!chain.TryGetAWSCredentials(options.Profile, out awsCredentials))
                {
                    Console.WriteLine($"Unable to retrieve credentials for profile {options.Profile}");
                    System.Environment.Exit(-3);
                    return -3;
                }

                CredentialProfile credentialProfile;
                if (!chain.TryGetProfile(options.Profile, out credentialProfile))
                {
                    Console.WriteLine($"Unable to retrieve credential profile for {options.Profile}");
                    System.Environment.Exit(-4);
                    return -4;
                }

                awsRegion = credentialProfile.Region ?? RegionEndpoint.GetBySystemName(options.Region);
            }
            else
            {
                if (string.IsNullOrWhiteSpace(options.AccessKeyId))
                {
                    Console.Error.WriteLine("No profile was specified, but an access key ID was not provided either.");
                    System.Environment.Exit(-5);
                    return -5;
                }

                if (string.IsNullOrWhiteSpace(options.AccessKeySecret))
                {
                    Console.Error.WriteLine("No profile was specified, but an access key secret was not provided either.");
                    System.Environment.Exit(-6);
                    return -6;
                }

                awsCredentials = new BasicAWSCredentials(options.AccessKeyId, options.AccessKeySecret);
                awsRegion = RegionEndpoint.GetBySystemName(options.Region);
            }

            var cts = new CancellationTokenSource();

            var getFindingsTask = Task.Run(async () =>
            {
                var client = new AmazonGuardDutyClient(awsCredentials, awsRegion);

                var detectorRequest = new ListDetectorsRequest();
                var detectorResponse = await client.ListDetectorsAsync(detectorRequest, cts.Token);

                foreach (var detectorId in detectorResponse.DetectorIds)
                {
                    var listFindingsRequest = new ListFindingsRequest()
                    {
                        DetectorId = detectorId,
                        /*FindingCriteria = new FindingCriteria
                        {
                            Criterion = { { "service.archived", new Condition { Eq = { "FALSE" } } } }
                        }*/
                    };

                    try
                    {
                        // Get list of findings
                        var listFindingsResponse = await client.ListFindingsAsync(listFindingsRequest, cts.Token);

                        // For the list, get the details
                        var getFindingsRequest = new GetFindingsRequest()
                        {
                            DetectorId = detectorId,
                            FindingIds = listFindingsResponse.FindingIds
                        };
                        var getFindingsResponse = await client.GetFindingsAsync(getFindingsRequest, cts.Token);

                        dynamic bundle = new ExpandoObject();
                        bundle.type = "bundle";
                        bundle.id = $"{detectorId}-{DateTime.UtcNow.ToString("o")}";
                        bundle.spec_version = "2.0";

                        var objects = new List<object>();
                        foreach (var finding in getFindingsResponse.Findings)
                        {
                            var sdo = await ConvertFindingToStixAsync(finding);
                            objects.Add(sdo);
                        }

                        bundle.objects = objects;


                        await Console.Out.WriteLineAsync(Newtonsoft.Json.JsonConvert.SerializeObject(bundle));
                    }
                    catch (Exception e)
                    {
                        await Console.Error.WriteLineAsync(e.ToString());
                    }
                }
            });
            Task.WaitAll(getFindingsTask);

            Console.WriteLine("Hello World!");
            return 0;
        }

        private static async Task<object> ConvertFindingToStixAsync(Finding finding)
        {
            // UUID should be deterministically determined from finding.Id
            byte[] bytes = Encoding.UTF8.GetBytes(finding.Id);
            var hashstring = new SHA256Managed();
            var hash = hashstring.ComputeHash(bytes);
            var uuid = new Guid(hash.Take(16).ToArray());

            var labels = new object[0];

            dynamic ret = new ExpandoObject();
            ret.id = $"indicator--{uuid}";
            ret.type = "indicator";
            ret.name = finding.Title;
            ret.description = finding.Description;
            ret.valid_from = DateTime.Parse(finding.CreatedAt).ToString("o");
            ret.created = DateTime.Parse(finding.CreatedAt).ToString("o");
            ret.modified = DateTime.Parse(finding.UpdatedAt).ToString("o");
            ret.external_references = new[]
            {
                    new {
                        source_name = "guardduty",
                        description = "Amazon Web Services GuardDuty Finding ID",
                        external_id = finding.Id
                    },
                    new {
                        source_name = "guardduty",
                        description = "Amazon Web Services GuardDuty Finding ARN",
                        external_id = finding.Arn
                    }
            };

            if (finding.Description != null && finding.Description.IndexOf("registered to an unusual organization") > -1)
                ret.labels = new[] { "anomalous-activity" };
            else if (finding.Description != null && finding.Description.IndexOf("under unusual circumstances") > -1)
                ret.labels = new[] { "anomalous-activity" };
            else if (finding.Description != null && finding.Description.IndexOf("is performing outbound port scans against remote host") > -1)
                ret.labels = new[] { "compromised" };
            else if (finding.Description != null && finding.Description.IndexOf("known malicious") > -1)
                ret.labels = new[] { "malicious-activity" };
            else if (finding.Description != null && finding.Description.IndexOf("specific location has not been seen before") > -1)
                ret.labels = new[] { "benign" };
            else
            {
                await Console.Error.WriteLineAsync("No known label for description.");
            }

            if (finding.Type != null && finding.Type.StartsWith("Recon:"))
            {
                ret.kill_chain_phases = new[] {
                    new {
                        kill_chain_name = "lockheed-martin-cyber-kill-chain",
                        phase_name = "reconnaissance"
                    }
                };
            }

            if (finding.Service.Action.AwsApiCallAction != null)
            {
                var remote = finding.Service.Action.AwsApiCallAction.RemoteIpDetails;
                if (remote != null)
                    ret.pattern = $"[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '{JsonConvert.ToString(remote.IpAddressV4)}/32')]";
                else
                    await Console.Error.WriteLineAsync("No known pattern for AWS API call action.");
            }
            else if (finding.Service.Action.NetworkConnectionAction != null)
            {
                var nca = finding.Service.Action.NetworkConnectionAction;
                if (nca.RemoteIpDetails != null)
                    ret.pattern = $"[(network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '{JsonConvert.ToString(nca.RemoteIpDetails.IpAddressV4)}/32')]";
                else
                    await Console.Error.WriteLineAsync("No known pattern for network connection action.");
            }
            else if (finding.Service.Action.PortProbeAction != null)
            {
                var sb = new StringBuilder("[");
                foreach (var probDetail in finding.Service.Action.PortProbeAction.PortProbeDetails)
                {
                    if (sb.Length > 1)
                        sb.Append(" OR ");

                    var org = probDetail.RemoteIpDetails.Organization;
                    var asn = org == null ? "" : $"autonomous-system:number = {JsonConvert.ToString(org.Asn)} AND autonomous-system:name = '{JsonConvert.ToString(org.AsnOrg)}' AND ";
                    sb.Append($"({asn}network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '{JsonConvert.ToString(probDetail.RemoteIpDetails.IpAddressV4)}/32')");
                }
                sb.Append("]");
                ret.pattern = sb.ToString();
            }
            else
                await Console.Error.WriteLineAsync("No known pattern for unhandled action.");

            return ret;
        }
    }
}
