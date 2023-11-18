#!/usr/bin/perl -w

# pve-desktop-manager
#
# Copyright (C) 2023 phibbs7
#
# This software is written by phibbs7 <https://github.com/phibbs7>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use Config;
use Config::IniFiles;
use Data::Dumper;
use DateTime;
use File::Temp;
use JSON;
use PVE::APIClient::LWP;
#use Strict;
use Tk;
require Tk::Table;

sub our_main;
sub error_msg_window;
sub create_login_window;
sub create_vm_list_window;

our_main;

sub http_get {
    # Deal with Perl's brain damage here....
    my ($https_enable, $hostname, $port, $path, $postdata, $ticket) = @_;

    if (defined $hostname && $hostname ne "") {
        if (! defined $port || $port eq "") {
            $port = "8006";
        }
        if (! defined $path) {
            $path = "";
        }
        if (! defined $postdata) {
            $postdata = "";
        }
        if (! defined $ticket) {
            $ticket = "";
        }

        # Clean up the uri path.
        $path =~ s{^/}{};
        $path =~ s{//+}{/};
        my $proto = $https_enable ? "https://" : "http://";
        my $url = $proto . $hostname . ":" . $port . '/api2/json/' . $path;

        my $response;
        my $request = HTTP::Request->new();
        if ($postdata ne "") {
            $request->uri("$url?$postdata");
        } else {
            $request->uri($url);
        }
        $request->method("GET");
        if ($ticket ne "") {
            $request->header('Cookie' => 'PVEAuthCookie=' . $ticket);
        }

        my $ua = LWP::UserAgent->new();
        $response = $ua->request($request);
        if ($response->is_success) {
            my $data = decode_json($response->decoded_content);
            if (ref $data eq "HASH" && exists $data->{data}) {
                if (ref $data->{data} eq "ARRAY") {
                    return wantarray ? @{$data->{data}} : $data->{data};
                } else {
                    return $data->{data};
                }
            } else {
                return 1;
            }
        }
    }
    return;
}

sub get_auth_realms {
    # Deal with Perl's brain damage here....
    my ($https_enable, $hostname, $port) = @_;
    if (defined $hostname && $hostname ne "") {
        my @domains_response = http_get($https_enable, $hostname, defined $port ? $port : "", "access/domains");
        print to_json(\@domains_response, { pretty => 1, canonical => 1});

        if (ref \@domains_response eq "ARRAY") {
            my @temp_domains = ();
            my @temp_descriptions = ();

            my $array_size = scalar @domains_response;
            printf("Size of domains_response: %d\n", $array_size);

            #print("@domains_response", "\n");
            foreach my $x (@domains_response) {
                # Contrary to what might seem correct here....
                # $x is a reference to a HASH object.
                # So it must be dereferenced before it can be used.
                # I.e. $x{"realm"} won't work to get the value.
                # Think C pointer to array. I.e. int val = ptr->[1];
                # Use $x-> Instead of $x
                if (ref $x eq "HASH" && $x->{"realm"} ne "") {
                    push(@temp_domains, $x->{"realm"});
                    if ($x->{"comment"} ne "") {
                        push(@temp_descriptions, $x->{"comment"});
                    } else {
                        push(@temp_descriptions, $x->{"realm"});
                    }
                }
            }

            if (scalar @temp_domains > 0) {
                print("Got domains: [", join("]  [", @temp_domains), "]\nGot descriptions: [", join("]  [", @temp_descriptions), "]\n");

                # Note: This is a set of references that needs to be deref'd using "@$varname".
                return \@temp_domains, \@temp_descriptions;
            } else {
                printf("%s\n", "Failed to get domains.\n");
            }
        } else {
            printf("%s\n", "Hog mangler.\n");
        }
    }
    return;
}

sub get_node_list {
    # Deal with Perl's brain damage here....
    my ($conn) = @_;

    my $ret_val = 0;
    my $ret_data = "999 Invalid argument.";

    if (defined $conn && defined $$conn) {
        my $pve_client = $$conn;

        eval {
            my $node_response = $pve_client->call("GET", "/cluster/resources", {"type" => "node"});
            if ($node_response) {
                #print to_json($node_response, { pretty => 1, canonical => 1 });
                my @temp_nodes = ();
                my $temp_arr = $$node_response{"data"};
                foreach my $x (@$temp_arr) {
                    if (ref $x eq "HASH" && $x->{"node"} ne "") {
                        push(@temp_nodes, $x->{"node"});
                    }
                }

                if (scalar @temp_nodes > 0) {
                    print("Got nodes: [", join("]  [", @temp_nodes), "]\n");

                    $ret_val = 1;
                    $ret_data = \@temp_nodes;
                } else {
                    $ret_val = 0;
                    $ret_data = "999 No nodes returned by server.\n";
                }
            } else {
                $ret_val = 0;
                $ret_data = "999 Invalid server response to get_node_list.\n";
            }
        };
        if ($@) {
            $ret_val = 0;
            $ret_data = "$@";
        }
    }

    return $ret_val, $ret_data;
}

sub get_vm_list {
    # Deal with Perl's brain damage here....
    my ($conn) = @_;

    my $ret_val = 0;
    my $ret_data = "999 Invalid argument.";

    if (defined $conn && defined $$conn) {
        my $pve_client = $$conn;

        eval {
            my $vm_response = $pve_client->call("GET", "/cluster/resources", {"type" => "vm"});
            if ($vm_response) {
                #print to_json($vm_response, { pretty => 1, canonical => 1 });
                my @temp_vm_ids = ();
                my @temp_vm_nodes = ();
                my @temp_vm_names = ();
                my @temp_vm_status = ();
                my $temp_arr = $$vm_response{"data"};
                foreach my $x (@$temp_arr) {
                    if (ref $x eq "HASH" && $x->{"vmid"} ne "") {
                        push(@temp_vm_ids, $x->{"vmid"});

                        # Get the cluster node for the VM.
                        if ($x->{"node"} ne "") {
                            push(@temp_vm_nodes, $x->{"node"});
                        } else {
                            push(@temp_vm_nodes, "UNKNOWN_NODE");
                        }

                        # Get the VM name.
                        if ($x->{"name"} ne "") {
                            push(@temp_vm_names, $x->{"name"});
                        } else {
                            push(@temp_vm_names, $x->{"vmid"});
                        }

                        # Check the status.
                        if ($x->{"status"} eq "stopped" ||
                            $x->{"status"} eq "running") {
                            push(@temp_vm_status, $x->{"status"});
                        } else {
                            push(@temp_vm_status, "UNKNOWN_STATUS");
                        }
                    }
                }

                if (scalar @temp_vm_ids > 0) {
                    print("Got VMs: [", join("]  [", @temp_vm_ids), "]\n");

                    $ret_val = 1;
                    @temp = (\@temp_vm_ids, \@temp_vm_nodes, \@temp_vm_names, \@temp_vm_status);
                    $ret_data = \@temp;
                } else {
                    $ret_val = 0;
                    $ret_data = "999 No VMs returned by server.\n";
                }
            } else {
                $ret_val = 0;
                $ret_data = "999 Invalid server response to get_vm_list.\n";
            }
        };
        if ($@) {
            $ret_val = 0;
            $ret_data = "$@";
        }
    }

    return $ret_val, $ret_data;
}

sub login_pve {
    # Deal with Perl's brain damage here....
    my ($https_enable, $hostname, $port, $username, $password) = @_;

    my $ret_val = 0;
    my $ret_data = "999 Invalid argument.";

    if (defined $hostname && $hostname ne "") {
        if ($username ne "" && $password ne "") {
            eval {
                my $conn = PVE::APIClient::LWP->new(
                    username => $username,
                    password => $password,
                    port => defined $port ? $port : "",
                    #ticket => $ticket,
                    #csrftoken => $csrftoken,
                    host => $hostname,
                    # allow manual fingerprint verification
                    manual_verification => 1,
                );

                my $res = $conn->get("/api2/json/", {});
                print to_json($res, { pretty => 1, canonical => 1});
                $ret_val = 1;
                $ret_data = \$conn;
            };
            if ($@) {
                $ret_val = 0;
                $ret_data = "$@";
            }
        } else {
            $ret_val = 0;
            $ret_data = "Username / Password not provided.\n";
        }
    }
    return $ret_val, $ret_data;
}

sub renew_login_ticket {
    # Deal with Perl's brain damage here....
    my ($our_globals) = @_;

    my $ret_val = 0;
    my $ret_data = "999 Unknown Error.\n";

    if (defined $our_globals && defined $$our_globals{"conn"} && defined $$our_globals{"login_ticket_timestamp"}) {
        my $temp_ref = $$our_globals{"conn"};
        my $pve_client = $$temp_ref;

        if ($$pve_client{ticket} ne "") {
            # The API has a ticket validity limit of 2 hours. If we haven't renewed the ticket before then, we need to
            # login again.
            my $ts = $$our_globals{"login_ticket_timestamp"};
            if (($ts + DateTime::Duration->new( hours => 2 )) > DateTime->now) {
                eval {
                    my $ticket_response = $pve_client->call(
                        "POST",
                        "/access/ticket",
                        { "username" => $$our_globals{"fq_user_name"}, "password" => $$pve_client{ticket} }
                    );

                    if (defined $ticket_response && defined $ticket_response->{"data"} &&
                        defined $ticket_response->{"data"}->{ticket} && $ticket_response->{"data"}->{CSRFPreventionToken}) {
                        # Update the issued timestamp.
                        $our_globals->{"login_ticket_timestamp"} = DateTime->now;

                        # Update stored client ticket and CSRF token.
                        my $response_data = $ticket_response->{"data"};
                        $pve_client->update_ticket($response_data->{ticket});
                        $pve_client->update_csrftoken($response_data->{CSRFPreventionToken});

                        $ret_val = 1;
                        $ret_data = "";
                    }
                };
                if ($@) {
                    $ret_val = 0;
                    $ret_data = "$@";
                }
            } else {
                $ret_val = -1;
                $ret_data = "999 Login ticket expired.\n";
            }
        } else {
            $ret_val = 0;
            $ret_data = "999 No valid ticket.\n";
        }
    } else {
        $ret_val = 0;
        $ret_data = "999 Invalid argument. Hog mangler.\n";
    }
    return $ret_val, $ret_data;
}

sub power_vm {
    my ($power_type, $vm_id, $node, $our_globals) = @_;

    my $ret_val = 0;
    my $ret_data = undef;

    if ($vm_id ne "" && $node ne "" && defined $our_globals &&
        defined $$our_globals{"conn"}) {
        my $temp_ref = $$our_globals{"conn"};
        my $pve_client = $$temp_ref;

        eval {
            if ($power_type == 0) {
                # Soft Toggle.
                my $state_response = $pve_client->call("GET", "/nodes/" . $node . "/qemu/" . $vm_id . "/status/current");
                print to_json($state_response, { pretty => 1, canonical => 1 });
                if ($$state_response{"data"}{"status"} eq "running") {
                    my $power_response = $pve_client->call("POST", "/nodes/" . $node . "/qemu/" . $vm_id . "/status/shutdown");
                    print to_json($power_response, { pretty => 1, canonical => 1 });
                    if ($$power_response{"data"} =~ /UPID/ &&
                        ($$power_response{"data"} =~ /qmshutdown/ ||
                         $$power_response{"data"} =~ /hashutdown/)) {
                        $ret_val = 1;
                        $ret_data = undef;
                    } else {
                        $ret_val = 0;
                        $ret_data = "999 Unknown response from server.\n";
                    }
                } else {
                    if ($$state_response{"data"}{"status"} eq "stopped") {
                        my $power_response = $pve_client->call("POST", "/nodes/" . $node . "/qemu/" . $vm_id . "/status/start");
                        print to_json($power_response, { pretty => 1, canonical => 1 });
                        if ($$power_response{"data"} =~ /UPID/ &&
                            ($$power_response{"data"} =~ /qmstart/ ||
                             $$power_response{"data"} =~ /hastart/)) {
                            $ret_val = 1;
                            $ret_data = undef;
                        } else {
                            $ret_val = 0;
                            $ret_data = "999 Unknown response from server.\n";
                        }
                    }
                }
            } else {
                if ($power_type == 1) {
                    # Power on.
                    my $power_response = $pve_client->call("POST", "/nodes/" . $node . "/qemu/" . $vm_id . "/status/start");
                    print to_json($power_response, { pretty => 1, canonical => 1 });
                    if ($$power_response{"data"} =~ /UPID/ &&
                        ($$power_response{"data"} =~ /qmstart/ ||
                         $$power_response{"data"} =~ /hastart/)) {
                        $ret_val = 1;
                        $ret_data = undef;
                    } else {
                        $ret_val = 0;
                        $ret_data = "999 Unknown response from server.\n";
                    }
                } else {
                    if ($power_type == 2) {
                        # Soft power off.
                        my $power_response = $pve_client->call("POST", "/nodes/" . $node . "/qemu/" . $vm_id . "/status/shutdown");
                        print to_json($power_response, { pretty => 1, canonical => 1 });
                        if ($$power_response{"data"} =~ /UPID/ &&
                            ($$power_response{"data"} =~ /qmshutdown/ ||
                             $$power_response{"data"} =~ /hashutdown/)) {
                            $ret_val = 1;
                            $ret_data = undef;
                        } else {
                            $ret_val = 0;
                            $ret_data = "999 Unknown response from server.\n";
                        }
                    } else {
                        if ($power_type == 3) {
                            # Force Shutdown.
                            my $power_response = $pve_client->call("POST", "/nodes/" . $node . "/qemu/" . $vm_id . "/status/stop");
                            print to_json($power_response, { pretty => 1, canonical => 1 });
                            if ($$power_response{"data"} =~ /UPID/ &&
                                ($$power_response{"data"} =~ /qmstop/ ||
                                 $$power_response{"data"} =~ /hastop/)) {
                                $ret_val = 1;
                                $ret_data = undef;
                            } else {
                                $ret_val = 0;
                                $ret_data = "999 Unknown response from server.\n";
                            }
                        } else {
                            if ($power_type == 4) {
                                # Force Reset.
                                my $power_response = $pve_client->call("POST", "/nodes/" . $node . "/qemu/" . $vm_id . "/status/reset");
                                print to_json($power_response, { pretty => 1, canonical => 1 });
                                if ($$power_response{"data"} =~ /UPID/ &&
                                    ($$power_response{"data"} =~ /qmreset/ ||
                                     $$power_response{"data"} =~ /hareset/)) {
                                    $ret_val = 1;
                                    $ret_data = undef;
                                } else {
                                    $ret_val = 0;
                                    $ret_data = "999 Unknown response from server.\n";
                                }
                            }
                        }
                    }
                }
            }
        };
        if ($@) {
            $ret_val = 0;
            $ret_data = "$@";
        }
    } else {
        $ret_val = 0;
        $ret_data = "999 Invalid Argument.\n";
    }
    return $ret_val, $ret_data;
}

sub console_vm {
    my ($vm_id, $node, $our_globals) = @_;

    my $ret_val = 0;
    my $ret_data = undef;

    if ($vm_id ne "" && $node ne "" && defined $our_globals &&
        defined $$our_globals{"conn"}) {
        my $temp_ref = $$our_globals{"conn"};
        my $pve_client = $$temp_ref;

        eval {
            my $config_response = $pve_client->call("GET", "/nodes/" . $node . "/qemu/" . $vm_id . "/config");
            print to_json($config_response, { pretty => 1, canonical => 1 });
            if ($$config_response{"data"}{"vga"} =~ /qxl/) {
                my $console_response = $pve_client->call("POST", "/nodes/" . $node . "/qemu/" . $vm_id . "/spiceproxy");
                print to_json($console_response, { pretty => 1, canonical => 1 });
                if (ref $console_response eq "HASH") {
                    $tmp = File::Temp->new( SUFFIX => '.vv', UNLINK => 0 );
                    print ("Console file: $tmp\n");
                    $ini = Config::IniFiles->new(-default => "virt-viewer");

                    my $data = $$console_response{"data"};
                    my %temp = %$data;
                    my @keys = keys %temp;
                    foreach $x (@keys) {
                        $ini->newval("virt-viewer", "$x", $temp{$x});
                    }
                    $ini->OutputConfigToFileHandle($tmp, 0);
                    $ret_val = 1;
                    $ret_data = "$tmp";
                    close($tmp);
                }

            } else {
                if ($$config_response{"data"}{"vga"} ne "none") {
                    print("WARNING: This probably won't work. The generated remote-viewer config's VNC ticket is rejected by the server.\n");

                    my $console_response = $pve_client->call("POST", "/nodes/" . $node . "/qemu/" . $vm_id . "/vncproxy");
                    print to_json($console_response, { pretty => 1, canonical => 1 });
                    if (ref $console_response eq "HASH") {
                        $tmp = File::Temp->new( SUFFIX => '.vv', UNLINK => 0 );
                        print ("Console file: $tmp\n");
                        $ini = Config::IniFiles->new(-default => "virt-viewer");

                        my $data = $$console_response{"data"};
                        my %temp = %$data;
                        my @keys = keys %temp;
                        my $proxy_pass = "";
                        my $proxy_port = "";
                        foreach $x (@keys) {
                            # Bug. remote-viewer cannot handle the ca flag on vnc connections.
                            # It throws an error about the ca entry not being a key-value pair, group or comment....
                            if ("$x" ne "cert") {
                                if ("$x" ne "ticket") {
                                    if ("$x" ne "port") {
                                        $ini->newval("virt-viewer", "$x", $temp{$x});
                                    } else {
                                        $ini->newval("virt-viewer", "$x", $temp{$x});
                                        $proxy_port =  $temp{$x};
                                    }
                                } else {
                                    $ini->newval("virt-viewer", "$x", $temp{$x});
                                    $ini->newval("virt-viewer", "password", $temp{$x});
                                    $proxy_pass = $temp{$x};
                                }
                            } else {
                                # Fix the Ini var name, and escape the newlines.
                                my $fix = "$temp{$x}";
                                $fix =~ s/\n/\\n/g;
                                $ini->newval("virt-viewer", "ca", $fix);
                            }
                        }
                        # Add missing ini vars.
                        $ini->newval("virt-viewer", "type", "vnc");
                        $ini->newval("virt-viewer", "host", $$our_globals{"server_name"});
                        $ini->newval("virt-viewer", "delete-this-file", 1);

                        # Note: This doesn't work.
                        # pve still errors out with "LC_PVE_TICKET not set, VNC proxy without password is forbidden TASK ERROR: Failed to run vncproxy."
                        $ini->newval(
                            "virt-viewer",
                            "proxy",
                            ($$our_globals{"https_enable"} ? "https://" : "http://") .
                             "$$our_globals{\"server_name\"}" . ":" . "$proxy_port" . "/?LC_PVE_TICKET=" . "$proxy_pass");
                        $ini->OutputConfigToFileHandle($tmp, 0);

                        $ret_val = 2;
                        $ret_data = "$tmp";
                        close($tmp);
                    }
                } else {
                    $ret_val = 0;
                    $ret_data = "999 NO CONSOLE\n";
                }
            }
        };
        if ($@) {
            print("Console Launch Error: $@\n");
        }
    }
    return $ret_val, $ret_data;
}

sub run_external_cmd {
    # Deal with Perl's brain damage here....
    my ($cmd, $arg, $our_globals) = @_;

    my $ret_val = 0;
    my $ret_data = "999 Unknown Error.\n";

    if ($cmd ne "" && $arg ne "") {

        # To support your OS, just add it below....

        

        # Linux.
        if ($Config{'osname'} eq "linux") {
            eval {
                    system <<~ "SHELL";
                        $cmd $arg > /dev/null 2>&1
                    SHELL
            };
            $ret_val = 1;
            $ret_data = "";
        } else {
            $ret_val = 0;
            $ret_data = "999 Unsupported host system.\n";
        }
    } else {
        $ret_val = 0;
        $ret_data = "999 Invalid arguements.\n";
    }

    return $ret_val, $ret_data;
}

sub run_remote_viewer {
    # Deal with Perl's brain damage here....
    my ($console_file, $our_globals) = @_;

    my $ret_val = 0;
    my $ret_data = "999 Unknown Error.\n";

    if ($console_file ne "") {
        ($ret_val, $ret_data) = run_external_cmd("xdg-open", $console_file, $our_globals);
        if ($ret_val > 0) {
            $ret_val = 1;
            $ret_data = "";
        } else {
            if ($ret_data =~ /999 Unsupported host system/i) {
                $ret_val = 0;
                $ret_data = "999 Unsupported host system. Please open $console_file manually.\n";
            } else {
                $ret_val = 0;
            }
        }
    } else {
        $ret_val = 0;
        $ret_data = "999 No console.vv file given.\n";
    }

    return $ret_val, $ret_data;
}

sub run_vnc_viewer {
    # Deal with Perl's brain damage here....
    my ($console_file, $our_globals) = @_;

    my $ret_val = 0;
    my $ret_data = "999 Unknown Error.\n";

    if ($console_file ne "") {
        ($ret_val, $ret_data) = run_external_cmd("xdg-open", $console_file, $our_globals);
        if ($ret_val > 0) {
            $ret_val = 1;
            $ret_data = "";
        } else {
            if ($ret_data =~ /999 Unsupported host system/i) {
                $ret_val = 0;
                $ret_data = "999 Unsupported host system. Please open $console_file manually.\n";
            } else {
                $ret_val = 0;
            }
        }
    } else {
        $ret_val = 0;
        $ret_data = "999 No console.vv file given.\n";
    }

    return $ret_val, $ret_data;
}

sub copy_array_to_listbox {
    # Deal with Perl's brain damage here....
    my ($listbox, $array) = @_;

    # OK, we're using the old ways(TM) here, because apparently
    # the Tk.Listbox's listvariable option requires a tcl formatted string
    # in perl. (We can't just use a regular list object.) We also cannot
    # use StringVar either. Meanwhile using "tie" just creates an immutable
    # listbox. (We can't change it's contents later.)
    #
    # So just use the old delete and insert methods, which are guaranteed to
    # work.
    if (ref $array eq "ARRAY" && scalar ${array} > 0 &&
        defined $listbox) {
        my $lbox_size = $listbox->size;
        if ($lbox_size > 0) {
            $listbox->selectionClear(0, $lbox_size);
            for (my $x = 0; $x < $lbox_size; $x++) {
                $listbox->delete(0);
            }
        }
        foreach my $x (@${array}) {
            $listbox->insert($listbox->size, $x);
        }
        $listbox->see(0);
        $listbox->activate(0);
        return $listbox;
    }
    return;
}

sub our_main {
    my @login_window_default_domain_list = ("Please input a hostname.");
    my @login_window_login_window_current_domain_desc_list = ();
    my @login_window_login_window_current_domain_vals_list = ();

    my %our_globals = ();

    my $ret_val = 0;
    my $ret_data;
    $our_globals{"conn"} = undef;
    $our_globals{"login_widget"} = MainWindow->new(-title => "Login");
    $our_globals{"login_window_selected_domain"} = "";

    create_login_window($our_globals{"login_widget"}, \%our_globals);

    MainLoop;
}

sub error_msg_window {
    # Deal with Perl's brain damage here....
    my ($current_window, $window_title, $message) = @_;
    my $errmsg = $current_window->messageBox(-icon => "error", -type => "Ok", -title => $window_title, -message => $message);
}

sub login_window_domains_list_box_on_select_funct {
    my ($event, $our_globals) = @_;
    my @cur_sel = ();

    if (defined $our_globals && defined $our_globals->{"login_window_domains_listbox"}) {
        # Check if we got an auth domain list, and if it has a valid selection.
        @cur_sel = $our_globals->{"login_window_domains_listbox"}->curselection;
        if (scalar @login_window_current_domain_desc_list > 0 &&
            scalar @cur_sel == 1) {
            $our_globals->{"login_window_selected_domain"} = $login_window_current_domain_vals_list[$cur_sel[0]];
        } else {
            $our_globals->{"login_window_selected_domain"} = "";
        }
    } else {
        $our_globals->{"login_window_selected_domain"} = "";
    }
    print("Selected Domain: [" .  $our_globals->{"login_window_selected_domain"} . "]\n");
    return;
}

sub login_window_login_button_funct {
    my ($event, $our_globals) = @_;
    my $login_ret = 0;
    my $data;
    my $temp_username = "";
    if (!defined $our_globals) {
        print("Error ! Globals not defined.");
        return;
    }
    # Check if we got an auth domain list, and if it has a valid selection.
    if (scalar @login_window_current_domain_desc_list > 0 &&
        $our_globals->{"login_window_selected_domain"} ne "") {
        # Check for @ in the username.
        if ("@" =~ /\Q$$our_globals{"user_name"}\E/i) {
            ($login_ret, $data) = login_pve($$our_globals{"https_enable"}, $$our_globals{"server_name"}, $$our_globals{"server_port"}, $$our_globals{"user_name"}, $$our_globals{"user_pass"});
        } else {
            $temp_username = $$our_globals{"user_name"} . "@" . $$our_globals{"login_window_selected_domain"};

            ($login_ret, $data) = login_pve($$our_globals{"https_enable"}, $$our_globals{"server_name"}, $$our_globals{"server_port"}, $temp_username, $$our_globals{"user_pass"});
        }
    } else {
        ($login_ret, $data) = login_pve($$our_globals{"https_enable"}, $$our_globals{"server_name"}, $$our_globals{"server_port"}, $$our_globals{"user_name"}, $$our_globals{"user_pass"});
    }

    # Check for valid login_ret.
    if ($login_ret && $data) {
        # Save the user name for renewing the ticket.
        if ($temp_username ne "") {
            $$our_globals{"fq_user_name"} = $temp_username;
        } else {
            $$our_globals{"fq_user_name"} = $$our_globals{"user_name"};
        }

        # Blank out the password.
        $$our_globals{"user_pass"} = "";

        # Put the connection object into the globals list.
        $$our_globals{"conn"} = $data;

        # Set the issue time for the login ticket.
        $$our_globals{"login_ticket_timestamp"} = DateTime->now;

        # Create the VM list window.
        ($login_ret, $data) = create_vm_list_window($our_globals);
        if ($login_ret > 0 && $data) {
            # Update the VM list window so it has valid data on show.
            my ($ret_var, $ret_data) = update_vm_list_window($our_globals);
            if ($ret_var > 0) {
                # Display the VM list window, and hide the login window.
                $$our_globals{"vm_list_widget"}->deiconify;
                $$our_globals{"login_widget"}->withdraw;
            } else {
                error_msg_window($$our_globals{"login_widget"}, "VM list error", (defined $data && length($data) > 0) ? $data : "Unknown error.");
            }
        } else {
            error_msg_window($$our_globals{"login_widget"}, "VM list error", (defined $data && length($data) > 0) ? $data : "Unknown error.");
        }
    } else {
        error_msg_window($$our_globals{"login_widget"}, "Login error", (defined $data && length($data) > 0) ? $data : "Unknown error.");
    }
}

sub login_window_get_auth_domains_button_funct {
    my ($event, $our_globals) = @_;
    my ($ref_domains, $ref_desc) = get_auth_realms($$our_globals{"https_enable"}, $$our_globals{"server_name"}, $$our_globals{"server_port"});
    if (ref $ref_domains eq "ARRAY" && scalar @${ref_domains} > 0 &&
        ref $ref_desc eq "ARRAY" && scalar @${ref_desc} > 0) {

        @login_window_current_domain_vals_list = ();
        push(@login_window_current_domain_vals_list, @$ref_domains);

        @login_window_current_domain_desc_list = ();
        push(@login_window_current_domain_desc_list, @$ref_desc);
        copy_array_to_listbox($$our_globals{"login_window_domains_listbox"}, \@login_window_current_domain_desc_list);
        $$our_globals{"login_window_domains_listbox"}->pack;
    } else {
        printf("%s\n", "Hog mangler. No domains.");
    }
}

sub create_login_window {
    # Deal with Perl's brain damage here....
    my ($mw, $our_globals) = @_;

    my $ret_val = 0;
    my $ret_data = "Unknown error.";

    if (defined $mw && defined $our_globals) {
        $$our_globals{"https_enable"} = 0;
        my $https_btn = $mw->Checkbutton(-text => 'Enable HTTPS', -variable => \$$our_globals{"https_enable"});
        $https_btn->select;
        $https_btn->pack;

        $mw->Label(-text => 'Enter Host Name')->pack;
        my $hostname = $mw->Entry(-width => 20, -textvariable => \$$our_globals{"server_name"});
        $hostname->bind('<KeyRelease-Return>', [ sub {
            login_window_get_auth_domains_button_funct(@_);
        }, $our_globals, ] );
        $hostname->pack;

        $mw->Label(-text => 'Enter Port Number')->pack;
        my $port = $mw->Entry(-width => 5, -textvariable => \$$our_globals{"server_port"});
        $port->pack;

        # Reset these global vars. (In case of reentrance.)
        @login_window_current_domain_desc_list = ();
        @login_window_current_domain_vals_list = ();

        # Yay, more perl brain damage....
        #
        # For those suffering under it, login_window_default_domain_list is defined in our_main,
        # which is the only caller of this sub. Therefore login_window_default_domain_list is in-scope.
        # But the interpreter complains anyway because this is the first and only occurrence of it in
        # this sub. The ******* thing should check the vars in-scope before complaining.
        no warnings 'once';
        push(@login_window_current_domain_desc_list, @login_window_default_domain_list);
        use warnings 'once';

        my %options = ( ReturnType => "index" );

        $mw->Label(-text => 'Authentication Domain')->pack;
        my $domains_listbox = $mw->Listbox(-selectmode => "single");
        copy_array_to_listbox($domains_listbox, \@login_window_current_domain_desc_list);
        $domains_listbox->bind('<KeyRelease-Return>' => sub {
            my ($box) = @_;
            $box->selectionClear(0, 'end');
            $box->selectionSet($box->index('active'));
            $box->selectionAnchor($box->index('active'));
            $box->see($box->index('active'));
            $box->eventGenerate('<<ListboxSelect>>');
        });
        $domains_listbox->bind('<<ListboxSelect>>' => [ sub {
            login_window_domains_list_box_on_select_funct(@_);
        }, $our_globals, ] );
        $domains_listbox->pack;
        $our_globals->{"login_window_domains_listbox"} = $domains_listbox;

        $mw->Label(-text => 'Enter User Name')->pack;
        my $username = $mw->Entry(-width => 20, -textvariable => \$$our_globals{"user_name"});
        $username->pack;

        $mw->Label(-text => 'Enter Password')->pack;
        my $password = $mw->Entry(-width => 20, -show => '*', -textvariable => \$$our_globals{"user_pass"});
        $password->bind('<KeyRelease-Return>', [ sub {
            login_window_login_button_funct(@_);
        }, $our_globals, ] );
        $password->pack;

        $mw->Button(
            -text => 'Login',
            # Yes, the extra sub is needed here. (Or it will execute connect_pve instantly when the button gets eval'd.)
            -command => [ sub {
                login_window_login_button_funct(undef, @_);
            }, $our_globals, ]
        )->pack;

        $mw->Button(
            -text => 'Get Authentication Domains',
            # Yes, the extra sub is needed here. (Or it will execute get_auth_realms instantly when the button gets eval'd.)
            -command => [ sub {
                login_window_get_auth_domains_button_funct(undef, @_);
            }, $our_globals, ]
        )->pack;

        $mw->Button(
            -text    => 'Quit',
            -command => sub { exit },
        )->pack;
        $ret_val = 1;
    }
    return $ret_val, $ret_data;
}

sub create_vm_list_window {
    # Deal with Perl's brain damage here....
    my ($our_globals) = @_;

    my $ret_val = 0;
    my $ret_data = "Unknown error.";

    if (defined $$our_globals{"conn"}) {
        # Destroy the window if it already exists.
        if (defined $$our_globals{"vm_list_widget"}) {
            $$our_globals{"vm_list_widget"}->destroy;
        }

        # Create the new window.
        my $mw = MainWindow->new(-title => "VM List");

        # Create the refresh button.
        $mw->Button(-text => "Refresh", -command => [ sub {
            my ($our_globals) = @_;
            my ($ret_val, $ret_data )= update_vm_list_window($our_globals);
            if ($ret_val <= 0) {
                print("VM list refresh error: ", (defined $ret_data && length($ret_data) > 0) ? $ret_data : "Unknown error.\n");
            }
        }, $our_globals ])->pack(-anchor => "ne");

        # Create the logout button.
        $mw->Button(-text => "Logout", -command => [ sub {
            my ($our_globals) = @_;
            $$our_globals{"conn"} = undef;
            $$our_globals{"login_widget"}->deiconify;
            $$our_globals{"vm_list_widget"}->withdraw;
        }, $our_globals ])->pack(-anchor => "ne");

        # Create the VM listbox.
        $mw->Label(-text => "Virtual Machines")->pack;
        my $vm_table = $mw->Table;
        $$our_globals{"vm_list_table"} = $vm_table;
        $vm_table->pack;

        # Create update timer.
        my $timer = Tk::After->new($mw, 300000, 'repeat', [ sub {
            my ($our_globals) = @_;

            my $ret_val = 0;
            my $ret_data = undef;

            # Renew the login ticket after one hour.
            if (($$our_globals{"login_ticket_timestamp"} + DateTime::Duration->new( "hours" => 1 )) >= DateTime->now) {
                ($ret_val, $ret_data) = renew_login_ticket($our_globals);
                if ($ret_val <= 0) {
                    print("Login ticket refresh error: ", (defined $ret_data && length($ret_data) > 0) ? $ret_data : "Unknown error.");
                    $$our_globals{"login_widget"}->deiconify;
                    $$our_globals{"vm_list_widget"}->withdraw;
                }
            }

            ($ret_val, $ret_data) = update_vm_list_window($our_globals);
            if ($ret_val <= 0) {
                print("VM list refresh error: ", (defined $ret_data && length($ret_data) > 0) ? $ret_data : "Unknown error.");
            }
        }, $our_globals ]);

        # Push the new window to the globals list.
        $$our_globals{"vm_list_widget"} = $mw;

        # Done.
        $ret_val = 1;
        $ret_data = $mw;
    } else {
        $ret_val = 0;
        $ret_data = "Invalid argument. Hog mangler.";
    }

    return $ret_val, $ret_data;
}

sub update_vm_list_window {
    # Deal with Perl's brain damage here....
    my ($our_globals) = @_;

    my $ret_val = 0;
    my $ret_data = "Unknown error.";

    if (defined $$our_globals{"vm_list_widget"} && defined $$our_globals{"conn"}) {
        # Get the node list.
        ($ret_val, $ret_data) = get_node_list($$our_globals{"conn"});
        if ($ret_val > 0 && ref $ret_data eq "ARRAY") {
            # Place the node list somewhere.
            my $node_list = $ret_data;

            # Get the VM list.
            ($ret_val, $ret_data) = get_vm_list($$our_globals{"conn"});
            if ($ret_val > 0 &&
                ref $ret_data eq "ARRAY") {

                # Clear the table.
                $$our_globals{"vm_list_table"}->clear;

                my @temp_arr = @$ret_data;
                my $vm_ids_ref = $temp_arr[0];
                my @vm_ids = @$vm_ids_ref;

                my $vm_nodes_ref = $temp_arr[1];
                my @vm_nodes = @$vm_nodes_ref;

                my $vm_names_ref = $temp_arr[2];
                my @vm_names = @$vm_names_ref;

                my $vm_status_ref = $temp_arr[3];
                my @vm_status = @$vm_status_ref;

                my $vm_list_size = scalar @vm_ids;
                print("VM List size: $vm_list_size\n");

                my $temp_obj = undef;
                for (my $x = 0; $x < $vm_list_size; $x++) {
                    # Create the ID label.
                    $temp_obj = $$our_globals{"vm_list_table"}->Label(-text => $vm_ids[$x]);
                    $$our_globals{"vm_list_table"}->put($x, 0, $temp_obj);

                    # Create the Name label.
                    $temp_obj = $$our_globals{"vm_list_table"}->Label(-text => "$vm_names[$x]");
                    $$our_globals{"vm_list_table"}->put($x, 1, $temp_obj);

                    # Create the Node label.
                    $temp_obj = $$our_globals{"vm_list_table"}->Label(-text => "$vm_nodes[$x]");
                    $$our_globals{"vm_list_table"}->put($x, 2, $temp_obj);

                    # Create the status label.
                    $temp_obj = $$our_globals{"vm_list_table"}->Label(-text => "$vm_status[$x]");
                    $$our_globals{"vm_list_table"}->put($x, 3, $temp_obj);

                    # Create the console button.
                    $temp_obj = $$our_globals{"vm_list_table"}->Button(-text => "Open Console",
                                                                       -state => $vm_status[$x] eq "running" ? "normal" : "disabled");
                    $temp_obj->configure(-command => [ sub {
                        my ($our_button, $our_globals) = @_;
                        my ($xpos, $ypos) = $our_button->parent->Posn($our_button);
                        my ($ret_val, $ret_data) = console_vm($our_button->parent->get($xpos, 0)->cget(-text),
                                                              $our_button->parent->get($xpos, 2)->cget(-text),
                                                              $our_globals);
                        if ($ret_val > 0) {
                            if ($ret_val == 1) {
                                ($ret_val, $ret_data) = run_remote_viewer($ret_data, $our_globals);
                                if ($ret_val <= 0) {
                                    error_msg_window($$our_globals{"vm_list_widget"}, "Console launch error", (defined $ret_data && length($ret_data) > 0) ? $ret_data : "Unknown error.");
                                }
                            } else {
                                if ($ret_val == 2) {
                                    ($ret_val, $ret_data) = run_vnc_viewer($ret_data, $our_globals);
                                    if ($ret_val <= 0) {
                                        error_msg_window($$our_globals{"vm_list_widget"}, "Console launch error", (defined $ret_data && length($ret_data) > 0) ? $ret_data : "Unknown error.");
                                    }
                                } else {
                                    error_msg_window($$our_globals{"vm_list_widget"},
                                        "Console launch error",
                                        (defined $ret_data && length($ret_data) > 0) ? "Unknown console type. Please open $ret_data manually." : "Unknown error.");
                                }
                            }
                        } else {
                            error_msg_window($$our_globals{"vm_list_widget"}, "Console launch error", (defined $ret_data && length($ret_data) > 0) ? $ret_data : "Unknown error.");
                        }
                    }, $temp_obj, $our_globals ]);
                    $$our_globals{"vm_list_table"}->put($x, 4, $temp_obj);

                    # Create the power button.
                    $temp_obj = $$our_globals{"vm_list_table"}->Button(-text => $vm_status[$x] eq "running" ? "Power off" : "Power on");
                    $temp_obj->configure(-command => [ sub {
                        my ($our_button, $our_globals) = @_;
                        my ($xpos, $ypos) = $our_button->parent->Posn($our_button);
                        my ($ret_val, $ret_data) = power_vm(0,
                            $our_button->parent->get($xpos, 0)->cget(-text),
                            $our_button->parent->get($xpos, 2)->cget(-text),
                            $our_globals);
                        if ($ret_val > 0) {
                            $our_button->configure(-state => "disabled");
                        } else {
                            error_msg_window($$our_globals{"vm_list_widget"}, "VM power state change error", (defined $ret_data && length($ret_data) > 0) ? $ret_data : "Unknown error.");
                        }
                    }, $temp_obj, $our_globals ]);
                    $$our_globals{"vm_list_table"}->put($x, 5, $temp_obj);

                    # Create the force shutdown button.
                    # Create the power button.
                    $temp_obj = $$our_globals{"vm_list_table"}->Button(-text => "Force Shutdown",
                                                                       -state => $vm_status[$x] eq "running" ? "normal" : "disabled");
                    $temp_obj->configure(-command => [ sub {
                        my ($our_button, $our_globals) = @_;
                        my ($xpos, $ypos) = $our_button->parent->Posn($our_button);
                        my ($ret_val, $ret_data) = power_vm(3,
                            $our_button->parent->get($xpos, 0)->cget(-text),
                            $our_button->parent->get($xpos, 2)->cget(-text),
                            $our_globals);
                        if ($ret_val > 0) {
                            $our_button->configure(-state => "disabled");
                        } else {
                            error_msg_window($$our_globals{"vm_list_widget"}, "VM force shutdown error", (defined $ret_data && length($ret_data) > 0) ? $ret_data : "Unknown error.");
                        }
                    }, $temp_obj, $our_globals ]);
                    $$our_globals{"vm_list_table"}->put($x, 6, $temp_obj);

                    # Create the reset button.
                    $temp_obj = $$our_globals{"vm_list_table"}->Button(-text => "Force Reset",
                                                                       -state => $vm_status[$x] eq "running" ? "normal" : "disabled");
                    $temp_obj->configure(-command => [ sub {
                        my ($our_button, $our_globals) = @_;
                        my ($xpos, $ypos) = $our_button->parent->Posn($our_button);
                        my ($ret_val, $ret_data) = power_vm(4,
                            $our_button->parent->get($xpos, 0)->cget(-text),
                            $our_button->parent->get($xpos, 2)->cget(-text),
                            $our_globals);
                        if ($ret_val > 0) {
                            $our_button->configure(-state => "disabled");
                        } else {
                            error_msg_window($$our_globals{"vm_list_widget"}, "VM force reset error", (defined $ret_data && length($ret_data) > 0) ? $ret_data : "Unknown error.");
                        }
                    }, $temp_obj, $our_globals ]);
                    $$our_globals{"vm_list_table"}->put($x, 7, $temp_obj);

                }

            } # No else block needed here, as ret_val and ret_data are set by get_vm_list.
        } # No else block needed here, as ret_val and ret_data are set by get_node_list.
    } else {
        $ret_val = 0;
        $ret_data = "Invalid argument. Hog mangler.";
    }

    return $ret_val, $ret_data;
}
