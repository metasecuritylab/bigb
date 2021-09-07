# dev: suwonchon(suwonchon@gmail.com)

labels = ['PLAYBOOK_01', 'PLAYBOOK_02', 'PLAYBOOK_03', 'PLAYBOOK_04', 'PLAYBOOK_05', 'PLAYBOOK_06', 'PLAYBOOK_07']
SCHEDULER.every '5s' do
data = [
  {
    label: 'First dataset',
    data: Array.new(labels.length) { rand(40..80) },
    backgroundColor: [ 'rgba(255, 99, 132, 0.2)' ] * labels.length,
    borderColor: [ 'rgba(255, 99, 132, 1)' ] * labels.length,
    borderWidth: 1,
  }, {
    label: 'Second dataset',
    data: Array.new(labels.length) { rand(40..80) },
    backgroundColor: [ 'rgba(255, 206, 86, 0.2)' ] * labels.length,
    borderColor: [ 'rgba(255, 206, 86, 1)' ] * labels.length,
    borderWidth: 1,
  }
]
options = { }


  send_event('radarchart', { labels: labels, datasets: data, options: options })
end