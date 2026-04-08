# LTD: Low-Overhead Topology Discovery using Programmable Data Planes

Existing topology discovery methods for programmable networks (e.g., SDN) heavily rely on controllers to process massive LLDP packets, causing severe overhead that increases linearly with link changes. Therefore, we propose LTD, the first mechanism offloading core topology discovery to programmable data planes. LTD adopts three key strategies: three-layered maximum offloading that distributes tasks across switch ASIC, OS, and controller; an OS-ASIC co-driven mechanism that utilizes the characteristics of programmable switches to achieve periodic link change identification; and a plug-and-play data structure for seamless topology view updates. 


## How to Run

It is recommended to use 4 terminals.

### Step 1: Start the network

```bash
make
```

### Step 2: Start the controller

In a new terminal:

```bash
python3 controller.py
```

### Step 3: Start Switch OS

In a new terminal:

```bash
sudo python3 switch_os.py
```

If you only want to run one switch:

```bash
sudo python3 switch_os.py --switch s1
```


## Simulate a link failure

For example, to bring down `s1` port `2`, in a new terminal:

```bash
python3 link_simulation.py --switch s1 --port 2 --action down
```

### Simulate link recovery or a new link

```bash
python3 link_simulation.py --switch s1 --port 2 --action up
```
