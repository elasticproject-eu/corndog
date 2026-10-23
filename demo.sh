demo_path="$(mktemp -d --suffix "corndog")"
corndog-source      --force --generate-keypair "$demo_path/corndog-source.key"
corndog-destination --force --generate-keypair "$demo_path/corndog-destination.key"

tmux has-session -t corndog-demo 2>/dev/null || tmux new-session -d -s corndog-demo
tmux send-keys -t corndog-demo:0 "corndog-ttp" Enter
until ss -Htln sport = :9705 | grep -q .; do sleep 1; done
tmux split-window -v -t corndog-demo:0 -l 70%
tmux split-window -h -t corndog-demo:0 -l 50%

tmux send-keys -t corndog-demo:0 "echo Test | corndog-destination --dest-private-key \"$demo_path/corndog-destination.key\" --source-public-key \"$demo_path/corndog-source.key.pub\" --ttp-addr localhost:9705" Enter
until ss -Htln sport = :7760 | grep -q .; do sleep 1; done

tmux select-pane -L


tmux send-keys -t corndog-demo:0 "echo '[RET] to start'; read; echo Test | corndog-source --source-private-key \"$demo_path/corndog-source.key\" --destination-public-key \"$demo_path/corndog-destination.key.pub\" --destination-addr localhost:7760 --ttp-addr localhost:9705 " Enter

tmux attach -t corndog-demo:0


#corndog-ttp

#


rm -rf "$demo_path"
